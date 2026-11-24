#!/usr/bin/env python3
"""
DEMO: Tao aplicado a evidencia digital.
Prueba que el metodo del ensayo se puede implementar y medir.
Sin dependencias externas: solo stdlib.
"""
import json, hashlib, math, re, ssl, sys, urllib.request
from datetime import datetime, timezone
from collections import Counter

CTX = ssl.create_default_context()
TIMEOUT = 15

# ── Capa 2: evidencia con procedencia ──────────────────────
def fetch(url, fuente, metodo):
    """Toda captura lleva: fuente, metodo, fecha, hash. Sin excepcion."""
    ev = {"fuente": fuente, "metodo": metodo, "url": url,
          "capturado": datetime.now(timezone.utc).isoformat(),
          "ok": False, "datos": None, "error": None}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "osint-evidence/0.1",
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as r:
            raw = r.read()
        ev["ok"] = True
        ev["datos"] = json.loads(raw)
        ev["hash_sha256"] = hashlib.sha256(raw).hexdigest()
        ev["bytes"] = len(raw)
    except Exception as e:
        ev["error"] = f"{type(e).__name__}: {str(e)[:80]}"
    return ev

# ── Fuentes estructuradas ──────────────────────────────────
def dns_a(dominio):
    return fetch(f"https://dns.google/resolve?name={dominio}&type=A", "dns.google", "DoH A")

def dns_txt(dominio):
    return fetch(f"https://dns.google/resolve?name={dominio}&type=TXT", "dns.google", "DoH TXT")

def rdap(dominio):
    tld = dominio.rsplit(".", 1)[-1]
    servidores = {
        "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
        "com": "https://rdap.verisign.com/com/v1/domain/",
        "net": "https://rdap.verisign.com/net/v1/domain/",
        "ec": "https://rdap.nic.ec/domain/",
    }
    base = servidores.get(tld)
    if not base:
        return {"fuente": "rdap", "metodo": "rdap", "ok": False,
                "error": f"sin servidor RDAP para .{tld}"}
    return fetch(base + dominio, f"rdap.{tld}", "RDAP")

def ct(dominio):
    return fetch(f"https://api.certspotter.com/v1/issuances?domain={dominio}"
                 f"&include_subdomains=true&expand=dns_names", "certspotter", "CT")

# ── Capa 3a: teoria de la informacion ──────────────────────
def entropia(s):
    if not s: return 0.0
    f = Counter(s); n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in f.values())

# ── Capa 3b: Bayes con priors declarados ───────────────────
PRIORS = {
    # P(mismo dueno) antes de ver nada. 1 de cada 100 pares examinados.
    "mismo_dueno": 0.01,
}

# Likelihood ratios: cuanto multiplica el ODDS la evidencia.
# Valores derivados de la literatura; declarados para que sean auditables.
LR = {
    "ip_compartida_hosting":  1.2,   # casi no informa: miles de dominios
    "ip_compartida_dedicada": 12.0,  # informa bastante
    "cert_compartido_wildcard": 2.0, # wildcard = CDN generico
    "cert_compartido_san":    18.0,  # SAN con pocos nombres = especifico
    "email_registro_igual":   60.0,  # muy especifico
    "nameserver_igual":       6.0,
    "registrador_igual":      1.05,  # todos .org usan el mismo
}

def bayes(evidencias):
    """Devuelve posterior y traza del calculo, paso a paso."""
    prior = PRIORS["mismo_dueno"]
    odds = prior / (1 - prior)
    traza = [("prior", prior, odds)]
    for ev in evidencias:
        lr = LR.get(ev["tipo"], 1.0)
        odds *= lr
        p = odds / (1 + odds)
        traza.append((ev["tipo"], p, odds))
    return odds / (1 + odds), traza

# ── Capa 3c: metodo de Tao — buscar el contraejemplo ───────
def contraejemplos(datos):
    """Tao: no confirmes, intenta romper tu propia hipotesis."""
    hallazgos = []

    # Contraejemplo 1: la IP pertenece a un CDN masivo
    ips = datos.get("ips", [])
    if ips:
        asn = fetch(f"https://api.bgpview.io/ip/{ips[0]}", "bgpview", "ASN")
        if asn["ok"]:
            datos["asn"] = asn
            pref = ((asn["datos"] or {}).get("data") or {}).get("prefixes") or []
            if pref:
                desc = (pref[0].get("asn") or {}).get("description", "").lower()
                datos["asn_desc"] = desc
                for cdn in ("cloudflare", "akamai", "fastly", "amazon", "google", "azure"):
                    if cdn in desc:
                        hallazgos.append({
                            "rompe": "ip_compartida_dedicada",
                            "razon": f"IP pertenece a {cdn} (hosting masivo)",
                            "efecto": "IP compartida NO informa sobre dueno",
                        })
                        break

    # Contraejemplo 2: el certificado es wildcard o SAN gigante
    ct_d = datos.get("ct") or {}
    nombres = datos.get("ct_nombres") or []
    if any(n.startswith("*.") for n in nombres):
        hallazgos.append({
            "rompe": "cert_compartido_san",
            "razon": "certificado wildcard (cubre subdominios, no identifica dueno)",
            "efecto": "cert compartido baja a peso de wildcard",
        })
    if len(nombres) > 20:
        hallazgos.append({
            "rompe": "cert_compartido_san",
            "razon": f"SAN con {len(nombres)} nombres (generico, no corporativo)",
            "efecto": "cert compartido NO identifica dueno",
        })

    # Contraejemplo 3: dominios reservados de documentacion
    reservados = {"example.com","example.org","example.net","example.edu"}
    if any(d in reservados for d in datos.get("dominios", [])):
        hallazgos.append({
            "rompe": "todo",
            "razon": "dominio reservado por IANA para documentacion",
            "efecto": "cualquier conclusion sobre propiedad es invalida",
        })

    return hallazgos

# ── Capa 4: informe con limites declarados ─────────────────
def analizar(dominios):
    print("=" * 74)
    print(f"  ANALISIS: {' vs '.join(dominios)}")
    print("=" * 74)

    datos = {"dominios": dominios, "fuentes": []}

    # Recoleccion con procedencia
    print("\n▸ CAPA 1 — Recoleccion")
    for d in dominios:
        r = dns_a(d); datos["fuentes"].append(r)
        ips = [a["data"] for a in (r["datos"] or {}).get("Answer", []) if a.get("type") == 1] if r["ok"] else []
        print(f"  {d:22} DNS A: {', '.join(ips) if ips else 'sin datos'}  [{r['fuente']}]")
        datos.setdefault("ips", []).extend(ips)

        r2 = rdap(d); datos["fuentes"].append(r2)
        if r2["ok"]:
            dd = r2["datos"]
            evs = {e.get("eventAction"): e.get("eventDate","")[:10] for e in dd.get("events",[])}
            print(f"  {'':22} RDAP: creado {evs.get('registration','?')} · "
                  f"expira {evs.get('expiration','?')}")
            datos.setdefault("rdap", {})[d] = dd

        r3 = ct(d); datos["fuentes"].append(r3)
        if r3["ok"] and isinstance(r3["datos"], list):
            nombres = sorted({n for x in r3["datos"] for n in (x.get("dns_names") or [])})
            print(f"  {'':22} CT: {len(r3['datos'])} certs · {len(nombres)} nombres")
            datos.setdefault("ct_nombres", []).extend(nombres)

    # ── Evaluacion
    print("\n▸ CAPA 3 — Evaluacion matematica")

    evidencias = []
    if len(set(datos.get("ips", []))) < len(dominios) and len(datos.get("ips", [])) > 0:
        evidencias.append({"tipo":"ip_compartida_hosting","valor":True})
    nombres = set(datos.get("ct_nombres", []))
    compartidos = nombres & set(dominios)
    if len(compartidos) > 0:
        tipo = "cert_compartido_wildcard" if any(n.startswith("*.") for n in nombres) else "cert_compartido_san"
        evidencias.append({"tipo":tipo,"valor":True})

    print(f"  Evidencias recolectadas: {len(evidencias)}")
    for e in evidencias:
        print(f"    · {e['tipo']:26} LR={LR.get(e['tipo'],1.0):>5}")

    # Contraejemplos ANTES de concluir (metodo Tao)
    print("\n▸ CAPA 3c — Busqueda de contraejemplos (metodo Tao)")
    ce = contraejemplos(datos)
    if ce:
        for c in ce:
            print(f"  ✗ ROMPE: {c['rompe']}")
            print(f"      razon: {c['razon']}")
            print(f"      efecto: {c['efecto']}")
        # aplicar: eliminar evidencias rotas
        rotas = {c["rompe"] for c in ce}
        if "todo" in rotas:
            evidencias = []
            print("  → TODAS las evidencias invalidadas")
        else:
            antes = len(evidencias)
            evidencias = [e for e in evidencias if e["tipo"] not in rotas]
            print(f"  → evidencias descartadas: {antes} → {len(evidencias)}")
    else:
        print("  ninguna encontrada — la hipotesis se sostiene")

    # Bayes final
    print("\n▸ CAPA 3b — Inferencia bayesiana")
    post, traza = bayes(evidencias)
    for nombre, p, odds in traza:
        print(f"  {nombre:28} P={p:.4f}  odds={odds:.3f}")
    print(f"\n  ► POSTERIOR: P(mismo dueno) = {post:.4f} = {post*100:.1f}%")

    # Limites declarados
    print("\n▸ CAPA 4 — Limites declarados")
    fallidas = [f for f in datos["fuentes"] if not f.get("ok")]
    print(f"  Fuentes consultadas: {len(datos['fuentes'])} · fallidas: {len(fallidas)}")
    for f in fallidas:
        print(f"    ✗ {f.get('fuente','?'):14} {f.get('error','?')[:52]}")
    if fallidas:
        print("  → confianza reducida: hay fuentes no verificadas")

    # Hash del informe (integridad)
    cuerpo = json.dumps({"dominios": dominios, "evidencias": evidencias,
                         "posterior": round(post, 6)},
                        sort_keys=True, ensure_ascii=False)
    h = hashlib.sha256(cuerpo.encode()).hexdigest()
    print(f"\n  hash del analisis: {h[:32]}…")
    print(f"  reproducible: misma entrada → mismo hash\n")

    return post, len(evidencias), len(ce), len(fallidas)


if __name__ == "__main__":
    casos = [
        ("example.org", "example.com"),   # dominio reservado IANA → debe romperse
        ("wikipedia.org", "wikimedia.org"),  # relacion real conocida
    ]
    for par in casos:
        analizar(list(par))
