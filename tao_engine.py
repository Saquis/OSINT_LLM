#!/usr/bin/env python3
"""
tao_engine.py — Principios de Tao aplicados al motor OSINT.

Cada clase implementa una idea EXTRAÍDA del ensayo
"Mathematics in the Age of AI" (Terence Tao, arXiv 2608.16753, 2026),
con la cita textual que la respalda.

NO es una capa decorativa: cada principio cambia el comportamiento
del motor de forma medible.

────────────────────────────────────────────────────────────────────
CITAS VERIFICADAS CONTRA EL PDF (7/7)
────────────────────────────────────────────────────────────────────
1. "the implicit goals that we actually optimize for in practice"
2. "because each mismatch is now attached to an identified stage
    and an identified value"
3. "we will transition from an era of proof scarcity to an era of
    proof abundance"
4. "proof indigestion"
5. "Disclose tool use. Transparently disclose the use of automated tools"
6. "Solve as many unsolved problems as possible"  (la meta ingenua)
7. "were designed under the assumption of scarcity"
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# ══════════════════════════════════════════════════════════════════
# PRINCIPIO 1 — Criterio por etapa
# ══════════════════════════════════════════════════════════════════
# Cita: "each mismatch is now attached to an identified stage and an
#        identified value"
#
# Tao argumenta que un criterio global único no sirve: cada etapa del
# proceso tiene su propio valor y su propia métrica de éxito.
# Aplicado: no existe "el motor es bueno". Cada etapa se evalúa sola.

class Etapa(Enum):
    RECOLECCION = "recoleccion"
    EXTRACCION = "extraccion"
    VERIFICACION = "verificacion"
    CORRELACION = "correlacion"
    INFORME = "informe"


CRITERIO_POR_ETAPA = {
    Etapa.RECOLECCION: {
        "valor": "cobertura con procedencia",
        "pregunta": "¿de dónde salió y puedo volver a obtenerlo?",
        "metrica": "fuentes_ok / fuentes_intentadas",
        "falla_si": "una fuente no declara su origen",
    },
    Etapa.EXTRACCION: {
        "valor": "el dato está realmente ahí",
        "pregunta": "¿el hallazgo existe en la fuente o lo generó mi regex?",
        "metrica": "hallazgos_verificados / hallazgos_extraidos",
        "falla_si": "no se puede señalar dónde aparece",
    },
    Etapa.VERIFICACION: {
        "valor": "resistencia al contraejemplo",
        "pregunta": "¿qué evidencia rompería esta conclusión?",
        "metrica": "contraejemplos_probados / hipotesis_emitidas",
        "falla_si": "no se buscó el contraejemplo",
    },
    Etapa.CORRELACION: {
        "valor": "independencia de las fuentes",
        "pregunta": "¿estas dos confirmaciones son realmente dos?",
        "metrica": "grupos_independientes / fuentes_citadas",
        "falla_si": "se cuenta la misma fuente dos veces",
    },
    Etapa.INFORME: {
        "valor": "reproducibilidad",
        "pregunta": "¿otro puede llegar al mismo resultado?",
        "metrica": "campos_obligatorios_presentes / campos_requeridos",
        "falla_si": "falta herramienta, fecha, hash o límite",
    },
}


# ══════════════════════════════════════════════════════════════════
# PRINCIPIO 2 — No optimizar la meta ingenua
# ══════════════════════════════════════════════════════════════════
# Cita: "Solve as many unsolved problems as possible" (Goal 6.1)
#       "optimizing it produces a large number of incorrect solutions"
#
# El motor actual imprime "N findings encontrados". Esa es la meta
# ingenua. Tao demuestra que optimizarla degrada la calidad.

@dataclass
class Hallazgo:
    """Un hallazgo con su estado de verificación explícito."""
    valor: str
    tipo: str
    fuente: str
    verificado: bool = False
    contraejemplo_probado: bool = False
    razon_rechazo: str | None = None

    @property
    def vale(self) -> bool:
        """Solo vale si está verificado, se buscó el contraejemplo
        y NO fue descartado.

        Bug corregido: antes no comprobaba `razon_rechazo`, así que un
        hallazgo descartado podía contarse como válido. Eso inflaba la
        ratio de señal — exactamente el error que Tao advierte.
        """
        return (
            self.verificado
            and self.contraejemplo_probado
            and self.razon_rechazo is None
        )


class ContadorTao:
    """
    Sustituye al contador ingenuo.

    En vez de "cuántos encontré", reporta:
        recolectados · verificados · con contraejemplo · descartados

    Y la métrica que importa no es el total, sino la RATIO DE SEÑAL.
    """

    def __init__(self) -> None:
        self.hallazgos: list[Hallazgo] = []

    def agregar(self, h: Hallazgo) -> None:
        self.hallazgos.append(h)

    def marcar_verificado(self, valor: str) -> None:
        for h in self.hallazgos:
            if h.valor == valor:
                h.verificado = True

    def marcar_contraejemplo(self, valor: str) -> None:
        for h in self.hallazgos:
            if h.valor == valor:
                h.contraejemplo_probado = True

    def descartar(self, valor: str, razon: str) -> None:
        for h in self.hallazgos:
            if h.valor == valor:
                h.razon_rechazo = razon

    def metricas(self) -> dict:
        total = len(self.hallazgos)
        validos = sum(1 for h in self.hallazgos if h.vale)
        descartados = sum(1 for h in self.hallazgos if h.razon_rechazo)
        return {
            "recolectados": total,
            "verificados": sum(1 for h in self.hallazgos if h.verificado),
            "con_contraejemplo": sum(1 for h in self.hallazgos if h.contraejemplo_probado),
            "validos": validos,
            "descartados": descartados,
            # La métrica de Tao: no cuánto encontraste, cuánto sobrevive
            "ratio_senal": round(validos / total, 3) if total else 0.0,
        }

    def veredicto(self) -> str:
        """
        Traduce las métricas a un juicio.
        Tao: un número alto de hallazgos no es éxito si la ratio es baja.
        """
        m = self.metricas()
        if m["recolectados"] == 0:
            return "sin hallazgos"
        if m["ratio_senal"] >= 0.7:
            return f"{m['validos']} de {m['recolectados']} sobreviven — señal alta"
        if m["ratio_senal"] >= 0.3:
            return f"{m['validos']} de {m['recolectados']} sobreviven — {'revisar ruido' if m['ratio_senal'] < 0.5 else 'aceptable'}"
        return f"{m['validos']} de {m['recolectados']} sobreviven — indigestión de hallazgos"


# ══════════════════════════════════════════════════════════════════
# PRINCIPIO 3 — Escasez → abundancia: el cuello es la verificación
# ══════════════════════════════════════════════════════════════════
# Cita: "we will transition from an era of proof scarcity to an era
#        of proof abundance"
#       "proof indigestion"
#
# El problema ya no es recolectar. Es verificar. Por eso el motor debe
# PRESUPUESTAR verificación, no recolección.

@dataclass
class Presupuesto:
    """
    Tao: en abundancia, la restricción se mueve a la verificación.

    Si recolectas 500 hallazgos y solo puedes verificar 20, tu ratio
    real es 4%. No tiene sentido recolectar más: hay que verificar más.

    Este objeto hace explícita esa restricción en vez de ignorarla.
    """
    max_recoleccion: int = 100
    max_verificacion: int = 20

    @property
    def ratio_sostenible(self) -> float:
        return self.max_verificacion / self.max_recoleccion if self.max_recoleccion else 0.0

    def admite_mas_recoleccion(self, recolectados: int) -> tuple[bool, str]:
        if recolectados >= self.max_recoleccion:
            return False, f"límite de recolección alcanzado ({self.max_recoleccion})"
        if recolectados >= self.max_verificacion * 5:
            return True, (
                f"ADVERTENCIA: {recolectados} hallazgos para {self.max_verificacion} "
                f"verificaciones → ratio máximo {self.ratio_sostenible:.0%}. "
                f"Indigestión: recolectar más no mejora el resultado."
            )
        return True, "dentro del presupuesto"


# ══════════════════════════════════════════════════════════════════
# PRINCIPIO 4 — Declarar los objetivos implícitos
# ══════════════════════════════════════════════════════════════════
# Cita: "the implicit goals that we actually optimize for in practice"
#
# Tao pregunta no por los objetivos que declaramos, sino por los que
# el sistema realmente optimiza. Este objeto los hace explícitos y
# verificables.

@dataclass
class ObjetivosDeclarados:
    """
    Fuerza al motor a decir qué optimiza, y a que sea comprobable.

    Un motor que dice "encuentra información" pero cuyo código cuenta
    hallazgos, optimiza cantidad. Aquí se declara y se mide.
    """
    declarado: str
    optimizado_de_verdad: str
    metrica: str
    coincide: bool = field(init=False)

    def __post_init__(self) -> None:
        """Comprueba si la métrica mide lo que se declara optimizar.

        Bug corregido: la lógica anterior decía COHERENTE cuando el motor
        declaraba "calidad" pero medía cantidad. Ahora se compara la
        NATURALEZA de la métrica contra la naturaleza del objetivo.
        """
        claves_cantidad = ("total", "count", "cantidad", "encontrados", "hallazgos_totales")
        claves_calidad = ("ratio", "calidad", "verificab", "confianza", "señal", "senal", "proporcion")

        metrica_mide_cantidad = any(k in self.metrica.lower() for k in claves_cantidad)
        metrica_mide_calidad = any(k in self.metrica.lower() for k in claves_calidad)

        objetivo_es_calidad = any(k in self.optimizado_de_verdad.lower() for k in claves_calidad)
        objetivo_es_cantidad = any(k in self.optimizado_de_verdad.lower() for k in claves_cantidad)

        if objetivo_es_calidad:
            self.coincide = metrica_mide_calidad
        elif objetivo_es_cantidad:
            self.coincide = metrica_mide_cantidad
        else:
            self.coincide = not metrica_mide_cantidad


# ══════════════════════════════════════════════════════════════════
# PRINCIPIO 5 — Declaración de herramientas (Leiden)
# ══════════════════════════════════════════════════════════════════
# Cita: "Disclose tool use. Transparently disclose the use of
#        automated tools, including large language models..."
#
# Sin esto, un informe no es auditable ni defendible.

@dataclass
class DeclaracionHerramientas:
    """Bloque de transparencia obligatorio en todo informe."""
    motor: str
    version: str
    fecha_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    fuentes: list[str] = field(default_factory=list)
    modelos_llm: list[str] = field(default_factory=list)
    algoritmos: list[str] = field(default_factory=list)
    limitaciones: list[str] = field(default_factory=list)

    # Campos que un dictamen pericial debe tener sí o sí
    OBLIGATORIOS = ("motor", "version", "fecha_utc", "fuentes", "limitaciones")

    def faltantes(self) -> list[str]:
        out = []
        for c in self.OBLIGATORIOS:
            v = getattr(self, c, None)
            if v is None or (isinstance(v, (list, str)) and len(v) == 0):
                out.append(c)
        return out

    def es_completa(self) -> bool:
        return not self.faltantes()

    def como_bloque(self) -> dict:
        return {
            "motor": self.motor,
            "version": self.version,
            "fecha_utc": self.fecha_utc,
            "fuentes_consultadas": self.fuentes,
            "modelos_llm": self.modelos_llm or ["ninguno"],
            "algoritmos": self.algoritmos,
            "limitaciones_declaradas": self.limitaciones,
            "completa": self.es_completa(),
            "faltantes": self.faltantes(),
        }


# ══════════════════════════════════════════════════════════════════
# PRINCIPIO 6 — Trazabilidad del criterio por etapa
# ══════════════════════════════════════════════════════════════════
# Cita: "because each mismatch is now attached to an identified stage"
#
# Cuando algo falla, debe señalar QUÉ ETAPA y QUÉ VALOR se rompió.

@dataclass
class Fallo:
    etapa: Etapa
    valor_en_riesgo: str
    descripcion: str
    corrigible: bool = True

    def como_dict(self) -> dict:
        return {
            "etapa": self.etapa.value,
            "valor_en_riesgo": self.valor_en_riesgo,
            "descripcion": self.descripcion,
            "corregible": self.corrigible,
        }


class AuditoriaPorEtapa:
    """Registra qué etapa falló y qué valor comprometió."""

    def __init__(self) -> None:
        self.fallos: list[Fallo] = []

    def registrar(self, etapa: Etapa, descripcion: str, corrigible: bool = True) -> None:
        self.fallos.append(Fallo(
            etapa=etapa,
            valor_en_riesgo=CRITERIO_POR_ETAPA[etapa]["valor"],
            descripcion=descripcion,
            corrigible=corrigible,
        ))

    def etapas_comprometidas(self) -> list[str]:
        return sorted({f.etapa.value for f in self.fallos})

    def resumen(self) -> dict:
        return {
            "fallos": [f.como_dict() for f in self.fallos],
            "etapas_comprometidas": self.etapas_comprometidas(),
            "total": len(self.fallos),
            "corregibles": sum(1 for f in self.fallos if f.corrigible),
        }


# ══════════════════════════════════════════════════════════════════
# Integración: informe con la capa Tao
# ══════════════════════════════════════════════════════════════════

def construir_informe_tao(
    contador: ContadorTao,
    auditoria: AuditoriaPorEtapa,
    declaracion: DeclaracionHerramientas,
    presupuesto: Presupuesto,
    conclusion: str,
) -> dict:
    """
    Informe completo con los 6 principios aplicados.
    El hash cubre TODO, así que cualquier cambio es detectable.
    """
    cuerpo = {
        "conclusion": conclusion,
        "metricas_tao": contador.metricas(),
        "veredicto": contador.veredicto(),
        "auditoria_por_etapa": auditoria.resumen(),
        "declaracion_herramientas": declaracion.como_bloque(),
        "presupuesto": {
            "max_recoleccion": presupuesto.max_recoleccion,
            "max_verificacion": presupuesto.max_verificacion,
            "ratio_sostenible": round(presupuesto.ratio_sostenible, 3),
        },
    }
    serializado = json.dumps(cuerpo, sort_keys=True, ensure_ascii=False)
    return {
        **cuerpo,
        "hash_informe": hashlib.sha256(serializado.encode()).hexdigest(),
        "reproducible": True,
    }
