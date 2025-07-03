#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Validador de E-mail – Versão 3.0
--------------------------------
• Refatorado para testar *todos* os MXs do domínio (ordem de prioridade).
• Mantém a geração inteligente de local-parts e detecção de catch-all.
• Continua forçando DNS público (8.8.8.8 / 8.8.4.4).
• Compatível com Python ≥ 3.8 (testado em 3.10/3.11).
"""

from __future__ import annotations

import asyncio
import itertools
import random
import re
import ssl
import string
import unicodedata
from typing import Dict, List, Sequence, Tuple

import aiosmtplib
import dns.resolver
from email_validator import EmailNotValidError, validate_email

###############################################################################
# Configuração de DNS – força uso do Google DNS para evitar timeouts/firewalls
###############################################################################

_PUBLIC_DNS = ["8.8.8.8", "8.8.4.4"]
resolver = dns.resolver.Resolver()
resolver.nameservers = _PUBLIC_DNS
dns.resolver.default_resolver = resolver  # torna global

###############################################################################
# Helpers de normalização e geração de combinações de local-part
###############################################################################

_SEPARATORS: Sequence[str] = ("", ".", "_", "-")
_DOM_REGEX = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

# Padrões de username. Use {first}, {f}, {middle}, {m}, {last}, {l}, {extra}, {sep}.
_USERNAME_TEMPLATES: Tuple[str, ...] = (
    "{first}",
    "{first}{sep}{last}", "{f}{sep}{last}", "{f}{l}",
    "{first}{sep}{l}", "{first}{last}",
    "{first}{middle}{last}", "{first}{sep}{middle}", "{first}{sep}{m}",
    "{f}{sep}{middle}",
    "{first}{sep}{middle}{sep}{last}", "{f}{sep}{m}{sep}{l}",
    "{f}{middle}{l}",
    "{first}{sep}{l}{sep}{extra}", "{f}{sep}{middle}{last}",
    "{first}{sep}{last}{sep}1", "{first}{sep}{last}{sep}01",
    "{first}{last}{extra}", "{f}{sep}{l}{sep}01", "{f}{l}{extra}",
    "{first}{sep}{l}1", "{first}{sep}{l}01", "{f}{sep}{last}{sep}1",
    "{first}{sep}{last}{sep}{extra}", "{first}{sep}{extra}",
    "{f}{sep}{l}{sep}{extra}", "{f}{sep}{last}{sep}{extra}",
    "{f}{middle}{sep}{last}", "{first}{sep}{m}{sep}{l}",
    "{first}{sep}{middle}{sep}{extra}", "{first}{sep}{middle}{l}",
    "{first}{sep}{middle}{sep}{last}{sep}1",
    "{f}{sep}{middle}{sep}{last}{sep}01", "{first}{middle}",
    "{first}{sep}{last}{sep}{m}", "{first}{sep}{l}{sep}{m}",
    "{f}{sep}{middle}", "{middle}{sep}{last}",
    "{last}{sep}{first}", "{l}{sep}{f}", "{last}{sep}{first}{sep}{extra}",
)

###############################################################################
# Funções utilitárias
###############################################################################


def _strip_accents(text: str) -> str:
    """Remove acentos e espaços, devolvendo em minúsculas e sem espaços."""
    nfkd = unicodedata.normalize("NFKD", text)
    sem_acento = "".join(c for c in nfkd if not unicodedata.combining(c))
    return re.sub(r"\s+", "", sem_acento.lower())


def _initial(text: str) -> str:
    return _strip_accents(text)[:1] if text else ""


def _rand_local(k: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=k))


_ERROR_MAP: Dict[str, str] = {
    "spamhaus": "Bloqueio Spamhaus",
    "authentication": "Precisa autenticar",
    "access denied": "Acesso negado",
    "timeout": "Timeout",
    "connection refused": "Conexão recusada",
}


def _short_error(msg: str) -> str:
    msg_low = msg.lower()
    for key, short in _ERROR_MAP.items():
        if key in msg_low:
            return short
    return msg_low.split("\n")[0][:50]


def generate_localparts(
    first: str,
    middle: str,
    last: str,
    extras: Sequence[str],
    limit: int = 1_000,
) -> List[str]:
    """Gera até *limit* local-parts diferentes a partir dos campos fornecidos."""

    subs = {
        "first": _strip_accents(first),
        "f": _initial(first),
        "middle": _strip_accents(middle),
        "m": _initial(middle),
        "last": _strip_accents(last),
        "l": _initial(last),
        "extra": _strip_accents(extras[0]) if extras else "",
    }

    bases: List[str] = []
    for tpl, sep in itertools.product(_USERNAME_TEMPLATES, _SEPARATORS):
        # pula padrões que dependem de middle/last inexistentes
        if ("middle" in tpl or "m" in tpl) and not middle:
            continue
        if ("last" in tpl or "l" in tpl) and not last:
            continue
        bases.append(tpl.format(**subs, sep=sep))

    # adiciona variações com extras
    out: List[str] = []
    for base in bases:
        out.append(base)
        for extra in extras:
            extra_norm = _strip_accents(extra)
            for sep in _SEPARATORS[1:]:  # ignora separador vazio
                out.append(f"{base}{sep}{extra_norm}")
        if len(out) >= limit:
            break

    # remove duplicatas preservando ordem
    return list(dict.fromkeys(out))[:limit]

###############################################################################
# Validador de domínio e e-mail
###############################################################################


class EmailValidatorAsync:
    """Valida endereços via SMTP (RCPT TO) de forma assíncrona."""

    def __init__(self, domain: str, concurrency: int = 20, light_mode: bool = False):
        self.domain = domain
        self._mx_cache: List[str] = []
        self._semaphore = asyncio.Semaphore(concurrency)
        self.light_mode = light_mode
        self._catch_all: bool | None = None

    # ------------------------------------------------------------------
    # MX helpers
    # ------------------------------------------------------------------

    async def _get_mx_hosts(self) -> List[str]:
        """Devolve todos os hosts MX, ordenados por preferência (cacheado)."""
        if not self._mx_cache:
            answers = dns.resolver.resolve(self.domain, "MX", lifetime=6)
            self._mx_cache = [
                str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda r: r.preference)
            ]
        return self._mx_cache

    # ------------------------------------------------------------------
    # SMTP validação
    # ------------------------------------------------------------------

    async def _smtp_check(self, email: str) -> Tuple[bool, str]:
        """
        Testa o RCPT TO em todos os MXs até obter resposta conclusiva.
        Retorna (ok, motivo).
        """

        if self.light_mode:
            return True, "MX OK (modo leve)"

        last_reason = "Falha desconhecida"
        for host in await self._get_mx_hosts():
            try:
                smtp = aiosmtplib.SMTP(
                    hostname=host,
                    timeout=9,
                    tls_context=ssl.create_default_context(),
                )
                await smtp.connect()
                await smtp.helo()
                await smtp.mail("test@local")
                code, _ = await smtp.rcpt(email)
                await smtp.quit()

                if code in (250, 251):
                    return True, f"{host}: RCPT {code}"
                last_reason = f"{host}: RCPT {code}"
            except Exception as exc:
                last_reason = f"{host}: {_short_error(str(exc))}"

        return False, last_reason

    # ------------------------------------------------------------------
    # Interface pública
    # ------------------------------------------------------------------

    async def validate(self, email: str) -> Tuple[str, bool, str]:
        """Valida formato + SMTP.  Retorna (email, ok, motivo)."""
        async with self._semaphore:
            try:
                validate_email(email, check_deliverability=False)
            except EmailNotValidError:
                return email, False, "Sintaxe inválida"

            ok, reason = await self._smtp_check(email)
            return email, ok, reason

    async def is_catch_all(self) -> bool:
        """Testa se o domínio aceita qualquer destinatário."""
        if self.light_mode:
            return False  # não testa catch-all em modo leve
        if self._catch_all is not None:
            return self._catch_all

        random_email = f"{_rand_local()}@{self.domain}"
        _, ok, _ = await self.validate(random_email)
        self._catch_all = ok
        return ok

###############################################################################
# Entrypoint interativo (CLI simples)
###############################################################################


async def _prompt_domain() -> str:
    """Pergunta domínio até que seja válido e tenha MX."""
    while True:
        dom = input("Domínio (ex: empresa.com): ").strip().lower()
        if not _DOM_REGEX.match(dom):
            print("❌ Formato inválido.\n")
            continue
        try:
            dns.resolver.resolve(dom, "MX", lifetime=5)
            return dom
        except Exception:
            print("❌ Domínio sem MX.\n")


def _banner() -> None:
    print("\n╔═════════════════════════════════════════════════╗")
    print("║         Validador de E-mail – Bitinho           ║")
    print("╚═════════════════════════════════════════════════╝\n")


async def run_interactive(light_mode: bool = False) -> None:  # noqa: C901
    _banner()

    domain = await _prompt_domain()

    first = input("Primeiro nome: ")
    middle = input("Nome do meio (ENTER p/ pular): ")
    last = input("Sobrenome (ENTER p/ pular): ")
    extras = input("Extras (departamento etc. – opcional): ").split()

    localparts = generate_localparts(first, middle, last, extras)
    emails = [f"{lp}@{domain}" for lp in localparts]

    print(f"🔧 {len(emails)} combinações geradas.")
    validator = EmailValidatorAsync(domain, concurrency=20, light_mode=light_mode)

    print(f"📡 MXs detectados: {', '.join(await validator._get_mx_hosts())}\n")
    print("🔍 Validando endereços… aguarde.\n")

    results = await asyncio.gather(*(validator.validate(e) for e in emails))

    spamhaus_cnt = sum(1 for _, ok, m in results if not ok and m == "Bloqueio Spamhaus")
    confirmed = [e for e, ok, _ in results if ok]

    if confirmed:
        print("✅ Confirmados:")
        for e in confirmed:
            print("   •", e, " ✔️")

    # Verifica catch-all
    if await validator.is_catch_all():
        print("\n⚠️  Domínio CATCH-ALL. Endereços prováveis:")
        for e in emails[:5]:
            print("   •", e, " ✔️")
    elif not confirmed:
        print("\n❌ Nenhum confirmado.")

    # Detecta possível bloqueio Spamhaus
    if not light_mode and spamhaus_cnt / len(results) >= 0.7:
        resp = input("\n⚠️  Seu IP parece bloqueado (Spamhaus). Rodar em modo LEVE? (s/n) ").lower()
        if resp.startswith("s"):
            print("\n🔄 Reexecutando em modo leve...\n")
            await run_interactive(light_mode=True)

###############################################################################
# Execução direta
###############################################################################

if __name__ == "__main__":
    try:
        asyncio.run(run_interactive())
    except KeyboardInterrupt:
        print("\nInterrompido.")
