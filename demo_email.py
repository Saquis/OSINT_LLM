#!/usr/bin/env python3
"""
Auditoria de exposicion de un correo propio.
Solo fuentes publicas y pasivas. Sin interaccion con el buzon.
Demuestra: procedencia, hash, evaluacion matematica.
"""
import hashlib, json, math, ssl, urllib.request
from datetime import datetime, timezone
from collections import Counter

CTX = ssl.create_default_context()
UA = {"User-Agent": "osint-evidence/0.1", "Accept": "application/json"}
TS = lambda: datetime.now(timezone.utc).isoformat()

def get(url, fuente, metodo):
    ev = {"fuente": fuente, "metodo": metodo, "capturado": TS(), "ok": False}
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
            raw = r.read()
        ev.update(ok=True, hash=hashlib.sha256(raw).hexdigest()[:16],
                  bytes=len(raw), datos=json.loads(raw))
    except Exception as e:
        ev["error"] = f"{type(e).__name__}"
    return ev

def dns(nombre, tipo):
    return get(f"https://dns.google/resolve?name={nombre}&type={tipo}",
               f"dns.google/{tipo}", f"DoH {tipo}")

def entropia(s):
    if not s: return 0.0
    f = Counter(s); n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in f.values())

def txt_records(ev):
    if not ev.get("ok"): return []
    return [a["data"].strip('"') for a in ev["datos"].get("Answer", []) if a.get("type") == 16]

def analizar(correo):
    local, dominio = correo.split("@", 1)
    fuentes = []

    print("=" * 72)
    print(f"  AUDITORIA DE EXPOSICION: {correo}")
    print("=" * 72)

    # ── 1. Proveedor (MX)
    print("\n▸ 1. Proveedor de correo (MX)")
    mx = dns(dominio, "MX"); fuentes.append(mx)
    if mx["ok"]:
        registros = [(a.get("data",""), a.get("name","")) for a in mx["datos"].get("Answer",[]) if a.get("type")==15]
        print(f"  servidores MX: {len(registros)}")
        for d, n in registros[:4]:
            print(f"    · {d}")
        proveedor = "proton" if any("proton" in d.lower() for d,_ in registros) else "desconocido"
        print(f"  proveedor detectado: {proveedor}")
    else:
        print(f"  ✗ {mx.get('error')}")

    # ── 2. Autenticacion de correo (SPF / DMARC)
    print("\n▸ 2. Autenticacion de correo (anti-suplantacion)")
    spf = dns(dominio, "TXT"); fuentes.append(spf)
    spf_txt = [t for t in txt_records(spf) if t.startswith("v=spf1")]
    print(f"  SPF: {spf_txt[0][:70] if spf_txt else '✗ NO EXISTE'}")
    if spf_txt:
        mecanismo = spf_txt[0].split()[-1] if spf_txt[0].split() else ""
        if mecanismo == "-all":
            print("    → -all (hardfail): rechaza servidores no autorizados")
        elif mecanismo == "~all":
            print("    → ~all (softfail): marca sospechoso pero acepta. "
                  "Proton lo usa por defecto para no romper el reenvío")
    else:
        print("    → sin SPF cualquiera puede falsificar el remitente")

    dmarc = dns(f"_dmarc.{dominio}", "TXT"); fuentes.append(dmarc)
    dm_txt = [t for t in txt_records(dmarc) if t.startswith("v=DMARC1")]
    print(f"  DMARC: {dm_txt[0][:70] if dm_txt else '✗ NO EXISTE'}")
    if dm_txt:
        politica = [p for p in dm_txt[0].split(";") if p.strip().startswith("p=")]
        print(f"    politica: {politica[0] if politica else 'no declarada'}")
    else:
        print(f"    → sin DMARC no hay política de rechazo de correos falsos")

    dkim_selector = dns(f"protonmail._domainkey.{dominio}", "TXT"); fuentes.append(dkim_selector)
    dk = txt_records(dkim_selector)
    print(f"  DKIM (protonmail): {'✓ presente' if dk else 'no encontrado (normal: selector interno)'}")

    # ── 3. Gravatar (foto publica vinculada)
    print("\n▸ 3. Gravatar — foto publica asociada al correo")
    h = hashlib.md5(correo.strip().lower().encode()).hexdigest()
    print(f"  hash MD5 del correo: {h}")
    gv = get(f"https://gravatar.com/{h}.json", "gravatar", "perfil publico")
    fuentes.append(gv)
    if gv["ok"]:
        perfil = gv["datos"].get("entry", [{}])[0]
        print(f"  ⚠️  PERFIL PUBLICO ENCONTRADO")
        print(f"     nombre:    {perfil.get('displayName','?')}")
        print(f"     usuario:   {perfil.get('preferredUsername','?')}")
        print(f"     foto:      {'sí' if perfil.get('thumbnailUrl') else 'no'}")
        print(f"     ubicación: {perfil.get('currentLocation','—')}")
        cuentas = perfil.get("accounts") or []
        if cuentas:
            print(f"     cuentas vinculadas: {len(cuentas)}")
            for a in cuentas[:5]:
                print(f"       · {a.get('shortname')}: {a.get('username')}")
    else:
        print(f"  ✅ sin perfil público (404) — el correo no está vinculado a Gravatar")

    # ── 4. Pwned check (HIBP sin key: solo el endpoint publico de rango)
    print("\n▸ 4. Exposicion en brechas")
    print("  HIBP requiere API key para consulta directa.")
    print("  Sin key, solo se puede saber si el dominio ha aparecido en brechas")

    # ── 5. Evaluacion de la parte local
    print("\n▸ 5. Fortaleza de la parte local")
    e = entropia(local)
    print(f"  parte local: '{local}'  ({len(local)} caracteres)")
    print(f"  entropia:    {e:.2f} bits/carácter  → {e*len(local):.1f} bits totales")
    if e*len(local) < 40:
        print(f"  ⚠️  por debajo de 40 bits: predecible por diccionario")
    else:
        print(f"  ✅ por encima de 40 bits")

    # ── 6. Limites declarados
    print("\n▸ 6. Limites de esta auditoria")
    fallidas = [f for f in fuentes if not f.get("ok")]
    print(f"  fuentes: {len(fuentes)} · fallidas: {len(fallidas)}")
    for f in fallidas:
        print(f"    ✗ {f['fuente']:22} {f.get('error','')}")
    print("  NO se consultó: contenido del buzon (E2E), brechas (sin API key),")
    print("                  registros de filtraciones comerciales, dark web")

    # ── 7. Hash del informe
    cuerpo = json.dumps({"correo": correo, "mx": bool(mx.get('ok')),
                         "spf": bool(spf_txt), "dmarc": bool(dm_txt),
                         "gravatar": bool(gv.get('ok'))}, sort_keys=True)
    print(f"\n  hash del analisis: {hashlib.sha256(cuerpo.encode()).hexdigest()[:32]}…")
    print()

if __name__ == "__main__":
    import sys

    # Uso: python demo_email.py tu-correo@dominio.com
    # No se incluye un correo real en el repositorio: el repo es público.
    if len(sys.argv) < 2:
        print("  uso: python demo_email.py correo@dominio.com")
        print("  (sin argumento no se consulta ningún correo)")
        raise SystemExit(1)

    analizar(sys.argv[1])
