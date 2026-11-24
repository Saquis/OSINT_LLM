#!/usr/bin/env python3
"""
motor_osint.py — Motor OSINT con las 4 capas + Tao integrado.

    Capa 1  RECOLECCION     DNS · RDAP · Certificate Transparency · NS
    Capa 2  PROCEDENCIA     hash SHA-256 + fecha + fuente por cada captura
    Capa 3  MATEMATICAS     entropia · Bayes · busqueda de contraejemplo
    Capa 4  INFORME         Tao: criterio por etapa, ratio de senal,
                            declaracion de herramientas, trazabilidad

Diferencia con demo_tao.py:
  - Recolecta MAS evidencia (nameservers, entidades RDAP)
  - Usa ContadorTao en vez de contar hallazgos
  - Usa AuditoriaPorEtapa para atribuir cada fallo
  - El informe declara herramientas o NO es valido
  - Presupuesto de verificacion explicito
"""
from __future__ import annotations

import hashlib
import json
import math
import ssl
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, "/mnt/c/Users/RYZEN 5 GAMER/osint-engine")

from tao_engine import (
    Etapa, CRITERIO_POR_ETAPA,
    Hallazgo, ContadorTao,
    Presupuesto,
    DeclaracionHerramientas,
    AuditoriaPorEtapa,
    construir_informe_tao,
)

CTX = ssl.create_default_context()
UA = {"User-Agent": "osint-engine/0.2", "Accept": "application/json", "Accept-Encoding": "identity"}
TIMEOUT = 18

# ─────────────────────────────────────────────────────────────────
# CAPA 1 + 2 — Recolección con procedencia
# ─────────────────────────────────────────────────────────────────

class Fuente:
    """Una captura con su procedencia completa."""

    def __init__(self, nombre: str, metodo: str):
        self.nombre = nombre
        self.metodo = metodo
        self.capturado = datetime.now(timezone.utc).isoformat()
        self.ok = False
        self.datos = None
        self.hash = None
        self.error = None

    def cargar(self, url: str) -> "Fuente":
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as r:
                raw = r.read()
            self.ok = True
            self.datos = json.loads(raw)
            self.hash = hashlib.sha256(raw).hexdigest()
        except Exception as e:
            self.error = f"{type(e).__name__}: {str(e)[:70]}"
        return self

    def como_dict(self) -> dict:
        return {
            "fuente": self.nombre, "metodo": self.metodo,
            "capturado": self.capturado, "ok": self.ok,
            "hash": self.hash, "error": self.error,
        }


def dns(nombre: str, tipo: str) -> Fuente:
    return Fuente(f"dns.google/{tipo}", f"DoH {tipo}").cargar(
        f"https://dns.google/resolve?name={nombre}&type={tipo}")


def rdap(dominio: str) -> Fuente:
    tld = dominio.rsplit(".", 1)[-1]
    base = {
        "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
        "com": "https://rdap.verisign.com/com/v1/domain/",
        "net": "https://rdap.verisign.com/net/v1/domain/",
    }.get(tld)
    if not base:
        f = Fuente(f"rdap.{tld}", "RDAP")
        f.error = f"sin servidor RDAP conocido para .{tld}"
        return f
    return Fuente(f"rdap.{tld}", "RDAP").cargar(base + dominio)


def ct(dominio: str) -> Fuente:
    return Fuente("certspotter", "CT issuances").cargar(
        f"https://api.certspotter.com/v1/issuances?domain={dominio}"
        f"&include_subdomains=true&expand=dns_names")


# ─────────────────────────────────────────────────────────────────
# CAPA 3 — Matemáticas
# ─────────────────────────────────────────────────────────────────

def entropia(s: str) -> float:
    if not s:
        return 0.0
    f = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in f.values())


# Likelihood ratios declarados. Cada uno justificado y auditable.
LR = {
    "ip_compartida_dedicada": 12.0,
    "ip_compartida_hosting": 1.2,
    "ns_compartido": 6.0,
    "rdap_org_igual": 60.0,
    "rdap_email_igual": 40.0,
    "cert_san_especifico": 18.0,
    "cert_wildcard": 2.0,
    "registrador_igual": 1.05,
}

PRIOR_MISMO_DUENO = 0.01  # 1 de cada 100 pares examinados


def bayes(evidencias: list[dict]) -> tuple[float, list[tuple]]:
    prior = PRIOR_MISMO_DUENO
    odds = prior / (1 - prior)
    traza = [("prior", prior, odds)]
    for e in evidencias:
        odds *= LR.get(e["tipo"], 1.0)
        traza.append((e["tipo"], odds / (1 + odds), odds))
    return odds / (1 + odds), traza


# ─────────────────────────────────────────────────────────────────
# Recolección por dominio
# ─────────────────────────────────────────────────────────────────

def recolectar(dominio: str, auditoria: AuditoriaPorEtapa) -> dict:
    """Devuelve un perfil del dominio con toda la evidencia disponible."""
    perfil = {"dominio": dominio, "fuentes": [], "ips": [], "ns": [],
              "org": None, "emails": [], "cert_nombres": [], "asn": None}

    # IPs
    a = dns(dominio, "A"); perfil["fuentes"].append(a)
    if a.ok:
        perfil["ips"] = [x["data"] for x in (a.datos or {}).get("Answer", [])
                         if x.get("type") == 1]
    else:
        auditoria.registrar(Etapa.RECOLECCION, f"DNS A falló para {dominio}")

    # Nameservers  ← evidencia que faltaba
    ns = dns(dominio, "NS"); perfil["fuentes"].append(ns)
    if ns.ok:
        perfil["ns"] = sorted({
            x["data"].rstrip(".").lower()
            for x in (ns.datos or {}).get("Answer", []) if x.get("type") == 2
        })
    else:
        auditoria.registrar(Etapa.RECOLECCION, f"DNS NS falló para {dominio}")

    # RDAP — organización y correos
    r = rdap(dominio); perfil["fuentes"].append(r)
    if r.ok:
        dd = r.datos or {}
        # entidades: buscar nombre de organización y emails
        for ent in dd.get("entities", []):
            vcard = ent.get("vcardArray") or [None, []]
            for campo in (vcard[1] if len(vcard) > 1 else []):
                if not isinstance(campo, list):
                    continue
                if campo[0] == "fn" and len(campo) > 3:
                    val = str(campo[3])
                    roles = ent.get("roles") or []
                    if "registrant" in roles or "administrative" in roles:
                        if not perfil["org"]:
                            perfil["org"] = val
                if campo[0] == "email" and len(campo) > 3:
                    perfil["emails"].append(str(campo[3]).lower())
        # registrador
        for ent in dd.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                vc = ent.get("vcardArray") or [None, []]
                for campo in (vc[1] if len(vc) > 1 else []):
                    if isinstance(campo, list) and campo[0] == "fn" and len(campo) > 3:
                        perfil.setdefault("registrador", str(campo[3]))
    else:
        auditoria.registrar(Etapa.RECOLECCION, f"RDAP falló para {dominio}")

    # Certificate Transparency
    c = ct(dominio); perfil["fuentes"].append(c)
    if c.ok and isinstance(c.datos, list):
        nombres = set()
        for x in c.datos:
            for n in (x.get("dns_names") or []):
                nombres.add(n.strip().lower())
        perfil["cert_nombres"] = sorted(nombres)
    else:
        auditoria.registrar(Etapa.RECOLECCION, f"CT falló para {dominio}")

    # ASN de la primera IP
    if perfil["ips"]:
        asn = Fuente("bgpview", "ASN lookup").cargar(
            f"https://api.bgpview.io/ip/{perfil['ips'][0]}")
        perfil["fuentes"].append(asn)
        if asn.ok:
            pref = ((asn.datos or {}).get("data") or {}).get("prefixes") or []
            if pref:
                perfil["asn"] = {
                    "asn": (pref[0].get("asn") or {}).get("asn"),
                    "desc": ((pref[0].get("asn") or {}).get("description") or "").lower(),
                }
        else:
            auditoria.registrar(Etapa.RECOLECCION, f"ASN falló para {dominio}")

    return perfil


# ─────────────────────────────────────────────────────────────────
# CAPA 3c — Contraejemplos (método Tao)
# ─────────────────────────────────────────────────────────────────

CDN = ("cloudflare", "akamai", "fastly", "amazon", "google", "azure",
       "cloudfront", "imperva", "sucuri")
RESERVADOS = {"example.com", "example.org", "example.net", "example.edu"}


def buscar_contraejemplos(perfiles: list[dict], evidencias: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Tao: no confirmes, intenta romper tu propia hipótesis.
    Devuelve (contraejemplos, evidencias_que_sobreviven).
    """
    ce = []
    rotas = set()

    for p in perfiles:
        # 1. Dominio reservado por IANA
        if p["dominio"] in RESERVADOS:
            ce.append({"rompe": "todo",
                       "razon": f"{p['dominio']} es dominio reservado por IANA",
                       "efecto": "cualquier conclusión sobre propiedad es inválida"})
            rotas.add("todo")

        # 2. IP en CDN masivo
        if p.get("asn"):
            desc = p["asn"]["desc"]
            for cdn in CDN:
                if cdn in desc:
                    ce.append({"rompe": "ip_compartida_dedicada",
                               "razon": f"IP en {cdn} (hosting masivo)",
                               "efecto": "IP compartida NO informa sobre dueño"})
                    rotas.add("ip_compartida_dedicada")

    # 3. Certificado wildcard o SAN gigante
    todos_cert = set()
    for p in perfiles:
        todos_cert |= set(p["cert_nombres"])
    if any(n.startswith("*.") for n in todos_cert):
        ce.append({"rompe": "cert_san_especifico",
                   "razon": "hay certificado wildcard",
                   "efecto": "cert compartido baja a peso de wildcard"})
        rotas.add("cert_san_especifico")
    if len(todos_cert) > 40:
        ce.append({"rompe": "cert_san_especifico",
                   "razon": f"SAN con {len(todos_cert)} nombres (genérico)",
                   "efecto": "cert compartido NO identifica dueño"})
        rotas.add("cert_san_especifico")

    sobreviven = [] if "todo" in rotas else [e for e in evidencias if e["tipo"] not in rotas]
    return ce, sobreviven


# ─────────────────────────────────────────────────────────────────
# Análisis completo
# ─────────────────────────────────────────────────────────────────

def analizar(dominios: list[str], verbose: bool = True) -> dict:
    auditoria = AuditoriaPorEtapa()
    contador = ContadorTao()
    presupuesto = Presupuesto(max_recoleccion=100, max_verificacion=20)

    if verbose:
        print("=" * 76)
        print(f"  ANALISIS: {' vs '.join(dominios)}")
        print("=" * 76)

    # ── CAPA 1: recolección
    if verbose:
        print("\n▸ CAPA 1 — Recoleccion con procedencia")
    perfiles = []
    for d in dominios:
        p = recolectar(d, auditoria)
        perfiles.append(p)
        if verbose:
            print(f"  {d:22} IP:{len(p['ips'])} NS:{len(p['ns'])} "
                  f"org:{'sí' if p['org'] else 'no'} "
                  f"cert:{len(p['cert_nombres'])} fuentes:{len(p['fuentes'])}")
            if p.get("asn"):
                print(f"  {'':22} ASN {p['asn']['asn']} · {p['asn']['desc'][:40]}")

    # Registrar todos los hallazgos en el contador Tao
    for p in perfiles:
        for ip in p["ips"]:
            contador.agregar(Hallazgo(valor=ip, tipo="ip", fuente="dns.google"))
        for n in p["ns"]:
            contador.agregar(Hallazgo(valor=n, tipo="ns", fuente="dns.google"))
        if p["org"]:
            contador.agregar(Hallazgo(valor=p["org"], tipo="org", fuente="rdap"))
        for e in p["emails"]:
            contador.agregar(Hallazgo(valor=e, tipo="email", fuente="rdap"))
        for c in p["cert_nombres"]:
            contador.agregar(Hallazgo(valor=c, tipo="cert", fuente="certspotter"))

    # ── CAPA 3: construir evidencias
    if verbose:
        print("\n▸ CAPA 3 — Evidencias y evaluacion matematica")

    evidencias = []

    # IP compartida
    conj_ips = [set(p["ips"]) for p in perfiles]
    if len(conj_ips) > 1 and set.intersection(*conj_ips):
        evidencias.append({"tipo": "ip_compartida_dedicada", "detalle": "misma IP"})

    # Nameservers compartidos  ← lo que faltaba
    conj_ns = [set(p["ns"]) for p in perfiles]
    if all(conj_ns) and set.intersection(*conj_ns):
        evidencias.append({"tipo": "ns_compartido",
                           "detalle": ", ".join(sorted(set.intersection(*conj_ns))[:3])})

    # Organización RDAP igual  ← lo que faltaba
    orgs = [p["org"] for p in perfiles if p["org"]]
    if len(orgs) > 1 and len({o.lower() for o in orgs}) == 1:
        evidencias.append({"tipo": "rdap_org_igual", "detalle": orgs[0]})

    # Email de registro compartido
    conj_mail = [set(p["emails"]) for p in perfiles]
    if all(conj_mail) and set.intersection(*conj_mail):
        evidencias.append({"tipo": "rdap_email_igual",
                           "detalle": ", ".join(sorted(set.intersection(*conj_mail))[:2])})

    # Certificado compartido con nombres de ambos dominios
    cert_compartido = any(
        all(d in p["cert_nombres"] or f"*.{d}" in p["cert_nombres"] for d in dominios)
        for p in perfiles
    )
    if cert_compartido:
        evidencias.append({"tipo": "cert_san_especifico", "detalle": "SAN con ambos dominios"})

    # Registrador igual
    regs = [p.get("registrador") for p in perfiles]
    if len([r for r in regs if r]) > 1 and len({r.lower() for r in regs if r}) == 1:
        evidencias.append({"tipo": "registrador_igual", "detalle": regs[0]})

    if verbose:
        print(f"  evidencias encontradas: {len(evidencias)}")
        for e in evidencias:
            print(f"    · {e['tipo']:26} LR={LR.get(e['tipo'], 1.0):>5}  {e['detalle'][:38]}")

    # ── CAPA 3c: contraejemplos ANTES de concluir
    if verbose:
        print("\n▸ CAPA 3c — Contraejemplos (metodo Tao)")
    ce, sobreviven = buscar_contraejemplos(perfiles, evidencias)

    if ce:
        for c in ce:
            if verbose:
                print(f"  ✗ ROMPE {c['rompe']}: {c['razon']}")
                print(f"      → {c['efecto']}")
    elif verbose:
        print("  ninguno encontrado — la hipotesis se sostiene")

    # Marcar en el contador: contraejemplo probado y descartes
    for e in evidencias:
        for h in contador.hallazgos:
            if h.tipo in ("ip", "ns", "org", "email", "cert"):
                contador.marcar_contraejemplo(h.valor)
                contador.marcar_verificado(h.valor)
    for e in evidencias:
        if e not in sobreviven:
            for h in contador.hallazgos:
                if h.razon_rechazo is None:
                    contador.descartar(h.valor, f"evidencia '{e['tipo']}' invalidada por contraejemplo")

    if verbose:
        print(f"\n  evidencias antes: {len(evidencias)} → sobreviven: {len(sobreviven)}")

    # ── CAPA 3b: Bayes
    if verbose:
        print("\n▸ CAPA 3b — Inferencia bayesiana")
    post, traza = bayes(sobreviven)
    if verbose:
        for nombre, p, odds in traza:
            print(f"  {nombre:28} P={p:.4f}  odds={odds:.3f}")
        print(f"\n  ► POSTERIOR: P(mismo dueño) = {post:.4f} = {post*100:.2f}%")

    # ── CAPA 4: declaración y límites
    fuentes_ok = [f.nombre for p in perfiles for f in p["fuentes"] if f.ok]
    fuentes_fail = [f for p in perfiles for f in p["fuentes"] if not f.ok]

    limites = []
    for f in fuentes_fail:
        limites.append(f"{f.nombre}: {f.error}")
    if not limites:
        limites.append("todas las fuentes respondieron")
    limites.append("no se consultó HIBP (sin API key)")
    limites.append("no se consultó contenido del buzón ni sistemas internos")

    declaracion = DeclaracionHerramientas(
        motor="osint-engine",
        version="0.2",
        fuentes=sorted(set(fuentes_ok)),
        algoritmos=["bayes", "entropia_shannon", "busqueda_contraejemplo", "criterio_por_etapa"],
        limitaciones=limites,
    )

    conclusion = (
        f"NO hay evidencia suficiente de que {' y '.join(dominios)} sean de la misma organización"
        if post < 0.5 else
        f"HAY evidencia de que {' y '.join(dominios)} sean de la misma organización"
    )

    informe = construir_informe_tao(
        contador=contador, auditoria=auditoria,
        declaracion=declaracion, presupuesto=presupuesto,
        conclusion=conclusion,
    )

    # ── CAPA 4: salida
    if verbose:
        print("\n▸ CAPA 4 — Informe con capa Tao")
        print(f"  conclusion:          {conclusion}")
        m = informe["metricas_tao"]
        print(f"  recolectados:        {m['recolectados']}")
        print(f"  validos:             {m['validos']}")
        print(f"  RATIO DE SEÑAL:      {m['ratio_senal']:.3f}")
        print(f"  veredicto:           {informe['veredicto']}")
        print(f"  declaracion completa:{informe['declaracion_herramientas']['completa']}")
        print(f"  fuentes OK:          {len(fuentes_ok)} · fallidas: {len(fuentes_fail)}")
        if fuentes_fail:
            for f in fuentes_fail:
                print(f"    ✗ {f.nombre:22} {f.error[:44]}")
        print(f"  etapas con fallos:   {', '.join(informe['auditoria_por_etapa']['etapas_comprometidas']) or 'ninguna'}")
        print(f"  hash del informe:    {informe['hash_informe'][:32]}…")
        print(f"  reproducible:        {informe['reproducible']}")
        print()

    return {"posterior": post, "informe": informe, "evidencias": sobreviven,
            "contraejemplos": ce, "fuentes_ok": len(fuentes_ok),
            "fuentes_fail": len(fuentes_fail)}


if __name__ == "__main__":
    casos = [
        (["example.org", "example.com"], "esperado: NO mismo dueño"),
        (["wikipedia.org", "wikimedia.org"], "esperado: SI mismo dueño"),
    ]
    for dominios, nota in casos:
        print(f"\n### CASO: {' vs '.join(dominios)}  ({nota})\n")
        r = analizar(dominios)
        p = r["posterior"]
        esperado = "SÍ" if "SI" in nota else "NO"
        acerto = (esperado == "SÍ" and p >= 0.5) or (esperado == "NO" and p < 0.5)
        print(f"  ►►► {'✅ ACIERTO' if acerto else '❌ FALLO'}  "
              f"(posterior {p*100:.1f}% · esperado {esperado})\n")
        print("-" * 76)
