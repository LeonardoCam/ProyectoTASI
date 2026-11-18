"""Lector propio de fechas WHOIS (reemplaza el intérprete de python-whois, que congelaba el servidor)."""
import datetime
import time

import pytest

from app import domain_info
from app.domain_info import creation_date

D = datetime.date

# Fragmentos reales de respuestas WHOIS de distintos registros.
JPRS = """[ JPRS database provides information on network administration. Its use is    ]
Domain Information:
[Domain Name]                   TRILLTRILL.JP
[Registrant]                    TRILL
[Name Server]                   ns-513.awsdns-00.net
[Created on]                    2014/05/27
[Last Updated]                  2026/06/01 01:05:03 (JST)
"""
VERISIGN = """   Domain Name: GOOGLE.COM
   Updated Date: 2019-09-09T15:39:04Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar Registration Expiration Date: 2028-09-13T07:00:00Z
"""


@pytest.mark.parametrize("text,expected", [
    (JPRS, D(2014, 5, 27)),
    (VERISIGN, D(1997, 9, 15)),                                    # no confunde la fecha de expiración
    ("created:       2004-10-24T20:00:00Z\nfree-date: 2027-11-25", D(2004, 10, 24)),   # .ru
    ("owner: X\ncreated:     19970711 #46903\ncreated:     19971217", D(1997, 7, 11)),  # .br (la más antigua)
    ("Registration Time: 2003-03-17 12:20:05", D(2003, 3, 17)),                     # .cn
    ("Domain record activated:    27-Jun-1985", D(1985, 6, 27)),                     # .edu
    ("    Registered on: before Aug-1996", D(1996, 8, 1)),                           # .uk
    ("Created: 24.10.2004", D(2004, 10, 24)),
    ("Sponsoring Registrar: NIC.PE\nRegistrant Name: BANCO DE CREDITO DEL PERU", None),  # .pe no publica fecha
    ("Creation Date: 2999-01-01", None),                                             # fecha futura: inválida
    ("", None),
])
def test_creation_date_formats(text, expected):
    assert creation_date(text) == expected


def test_parser_is_linear_on_hostile_input():
    """El intérprete de python-whois tardaba 91 s con 1,3 KB; el propio debe ser instantáneo."""
    hostile = ("[Created on]" + " " * 5000 + "x\n") * 200 + "Creation Date: " + "1" * 10000 + "\n" + JPRS * 50
    t = time.process_time()
    creation_date(hostile)
    assert time.process_time() - t < 0.5


async def test_domain_age_uses_parser_and_caches(monkeypatch):
    domain_info._whois_cache.clear()
    calls = []

    def fake_fetch(domain):
        calls.append(domain)
        return JPRS

    monkeypatch.setattr(domain_info, "_fetch", fake_fetch)
    age = await domain_info.domain_age_days("trilltrill.jp")
    assert age == (datetime.date.today() - D(2014, 5, 27)).days
    assert await domain_info.domain_age_days("trilltrill.jp") == age and calls == ["trilltrill.jp"]
