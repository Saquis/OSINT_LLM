#!/usr/bin/env python3
"""
prueba_tao.py — Demuestra que los 6 principios de Tao CAMBIAN
el comportamiento del motor, no solo lo decoran.

Caso: analizar si dos dominios son de la misma organizacion.
Se compara el motor ingenuo (contar hallazgos) contra el motor
con la capa Tao (criterio por etapa + contraejemplo + presupuesto).
"""
import sys
sys.path.insert(0, '/mnt/c/Users/RYZEN 5 GAMER/osint-engine')

from tao_engine import (
    Etapa, CRITERIO_POR_ETAPA,
    Hallazgo, ContadorTao,
    Presupuesto,
    ObjetivosDeclarados,
    DeclaracionHerramientas,
    AuditoriaPorEtapa,
    construir_informe_tao,
)


print("=" * 74)
print("  PRINCIPIO 1 — Criterio por etapa")
print("=" * 74)
print("  Cita: 'each mismatch is now attached to an identified stage")
print("         and an identified value'")
print()
for etapa, c in CRITERIO_POR_ETAPA.items():
    print(f"  {etapa.value.upper():14}")
    print(f"    valor:    {c['valor']}")
    print(f"    pregunta: {c['pregunta']}")
    print(f"    falla si: {c['falla_si']}")
    print()


print("=" * 74)
print("  PRINCIPIO 2 — No optimizar la meta ingenua")
print("=" * 74)
print("  Cita: 'Solve as many unsolved problems as possible' (Goal 6.1)")
print("         'optimizing it produces a large number of incorrect solutions'")
print()

contador = ContadorTao()

# Simulacion: el motor recolecta 10 hallazgos sobre dos dominios
hallazgos_simulados = [
    ("example.org",  "dominio",      "rdap"),
    ("example.com",  "dominio",      "rdap"),
    ("104.20.26.136","ip",           "dns.google"),
    ("*.example.org","certificado",  "certspotter"),
    ("example.edu",  "certificado",  "certspotter"),
    ("example.net",  "certificado",  "certspotter"),
    ("ns1.example.org","nameserver", "dns.google"),
    ("registrar-376","registrador",  "rdap"),
    ("SOA-MASTER",   "soa",          "dns.google"),
    ("TTL-3600",     "ttl",          "dns.google"),
]
for valor, tipo, fuente in hallazgos_simulados:
    contador.agregar(Hallazgo(valor=valor, tipo=tipo, fuente=fuente))

print(f"  Motor INGENUO diria: '✓ {len(hallazgos_simulados)} hallazgos encontrados'")
print("  (esa es la meta que Tao demuestra que degrada la calidad)")
print()

# Aplicando Tao: verificar y buscar contraejemplo
contador.marcar_verificado("example.org")
contador.marcar_contraejemplo("example.org")
contador.marcar_verificado("example.com")
contador.marcar_contraejemplo("example.com")
contador.descartar("example.org", "dominio reservado IANA (no identifica dueno)")
contador.descartar("example.com", "dominio reservado IANA (no identifica dueno)")

contador.marcar_verificado("104.20.26.136")
contador.marcar_contraejemplo("104.20.26.136")
contador.descartar("104.20.26.136", "IP de Cloudflare: miles de dominios comparten")

contador.marcar_verificado("*.example.org")
contador.marcar_contraejemplo("*.example.org")
contador.descartar("*.example.org", "certificado wildcard: no identifica dueno")

contador.marcar_verificado("example.edu")
contador.descartar("example.edu", "SAN generico de documentacion IANA")

contador.marcar_verificado("example.net")
contador.descartar("example.net", "SAN generico de documentacion IANA")

contador.marcar_verificado("ns1.example.org")
contador.marcar_contraejemplo("ns1.example.org")
contador.descartar("ns1.example.org", "mismo dominio, no es evidencia independiente")

contador.marcar_verificado("registrar-376")
contador.descartar("registrar-376", "registrador de todo .org (ICANN)")

contador.descartar("SOA-MASTER", "no identifica organizacion")
contador.descartar("TTL-3600", "parametro tecnico, no identifica dueno")

m = contador.metricas()
print("  Motor CON TAO reporta:")
print(f"    recolectados:       {m['recolectados']}")
print(f"    verificados:        {m['verificados']}")
print(f"    con contraejemplo:  {m['con_contraejemplo']}")
print(f"    validos:            {m['validos']}")
print(f"    descartados:        {m['descartados']}")
print(f"    RATIO DE SEÑAL:     {m['ratio_senal']:.3f}")
print()
print(f"  Verdicto: {contador.veredicto()}")
print()


print("=" * 74)
print("  PRINCIPIO 3 — Escasez → abundancia (presupuesto de verificacion)")
print("=" * 74)
print("  Cita: 'we will transition from an era of proof scarcity to an")
print("         era of proof abundance' / 'proof indigestion'")
print()

p = Presupuesto(max_recoleccion=100, max_verificacion=20)
print(f"  presupuesto: recolectar {p.max_recoleccion} · verificar {p.max_verificacion}")
print(f"  ratio sostenible: {p.ratio_sostenible:.0%}")
print()
for recolectados in (10, 50, 100, 150):
    ok, msg = p.admite_mas_recoleccion(recolectados)
    marca = "OK " if ok and "ADVERTENCIA" not in msg else ("!! " if ok else "XX ")
    print(f"  {marca} {recolectados:3} hallazgos → {msg}")
print()


print("=" * 74)
print("  PRINCIPIO 4 — Objetivos implicitos")
print("=" * 74)
print("  Cita: 'the implicit goals that we actually optimize for in practice'")
print()

casos_obj = [
    ObjetivosDeclarados(
        declarado="encontrar informacion relevante",
        optimizado_de_verdad="cantidad de hallazgos",
        metrica="total hallazgos encontrados",
    ),
    ObjetivosDeclarados(
        declarado="producir hallazgos verificables",
        optimizado_de_verdad="calidad verificable",
        metrica="ratio de senal (validos/recolectados)",
    ),
    # El caso real: el motor ACTUAL de osint-engine
    ObjetivosDeclarados(
        declarado="encontrar informacion relevante y verificable",
        optimizado_de_verdad="calidad verificable",
        metrica="total de findings unicos extraidos",
    ),
]
for o in casos_obj:
    estado = "COHERENTE" if o.coincide else "INCOHERENTE"
    print(f"  declara:  {o.declarado}")
    print(f"  optimiza: {o.optimizado_de_verdad}")
    print(f"  mide:     {o.metrica}")
    print(f"  → {estado}")
    print()


print("=" * 74)
print("  PRINCIPIO 5 — Declaracion de herramientas (Leiden)")
print("=" * 74)
print("  Cita: 'Disclose tool use. Transparently disclose the use of")
print("         automated tools, including large language models'")
print()

d_incompleta = DeclaracionHerramientas(
    motor="osint-engine",
    version="0.1",
    fuentes=["dns.google", "rdap.publicinterestregistry.org"],
)
print(f"  declaracion MINIMA:")
print(f"    completa: {d_incompleta.es_completa()}")
print(f"    faltan:   {d_incompleta.faltantes()}")
print(f"    → un dictamen con esto NO es defendible")
print()

d_completa = DeclaracionHerramientas(
    motor="osint-engine",
    version="0.1",
    fuentes=["dns.google", "rdap.publicinterestregistry.org", "certspotter"],
    algoritmos=["bayes", "entropia_shannon", "busqueda_contraejemplo"],
    limitaciones=[
        "certspotter no cubre todo el historial de CT",
        "no se consulto HIBP (sin API key)",
        "dominios reservados por IANA invalidan conclusion de propiedad",
    ],
)
print(f"  declaracion COMPLETA:")
print(f"    completa: {d_completa.es_completa()}")
print(f"    fuentes:  {len(d_completa.fuentes)}")
print(f"    limites:  {len(d_completa.limitaciones)} declarados")
print(f"    → este bloque SI es defendible")
print()


print("=" * 74)
print("  PRINCIPIO 6 — Trazabilidad por etapa")
print("=" * 74)
print("  Cita: 'each mismatch is now attached to an identified stage'")
print()

aud = AuditoriaPorEtapa()
aud.registrar(Etapa.RECOLECCION, "crt.sh devolvio 502 dos veces", corrigible=True)
aud.registrar(Etapa.EXTRACCION, "2 hallazgos sin ubicacion en la fuente", corrigible=True)
aud.registrar(Etapa.VERIFICACION, "no se probo contraejemplo en 3 hipotesis", corrigible=True)
aud.registrar(Etapa.CORRELACION, "certspotter y crt.sh cuentan como 1, no 2", corrigible=False)

r = aud.resumen()
print(f"  fallos registrados: {r['total']}")
for f in r["fallos"]:
    print(f"    [{f['etapa']:13}] {f['descripcion']}")
    print(f"                    valor en riesgo: {f['valor_en_riesgo']}")
print(f"  etapas comprometidas: {', '.join(r['etapas_comprometidas'])}")
print()


print("=" * 74)
print("  INFORME FINAL CON LA CAPA TAO")
print("=" * 74)

informe = construir_informe_tao(
    contador=contador,
    auditoria=aud,
    declaracion=d_completa,
    presupuesto=p,
    conclusion="NO hay evidencia de que example.org y example.com sean de la misma organizacion",
)
print(f"  conclusion:        {informe['conclusion']}")
print(f"  ratio de senal:    {informe['metricas_tao']['ratio_senal']}")
print(f"  veredicto:         {informe['veredicto']}")
print(f"  declaracion ok:    {informe['declaracion_herramientas']['completa']}")
print(f"  etapas afectadas:  {', '.join(informe['auditoria_por_etapa']['etapas_comprometidas'])}")
print(f"  hash del informe:  {informe['hash_informe'][:40]}…")
print(f"  reproducible:      {informe['reproducible']}")
print()
print("  → Cada linea de este informe cita un principio del ensayo.")
print("  → Sin la capa Tao, el motor diria '10 hallazgos encontrados'.")
print("  → Con Tao, dice '0 de 10 sobreviven — indigestion de hallazgos'.")
print()
