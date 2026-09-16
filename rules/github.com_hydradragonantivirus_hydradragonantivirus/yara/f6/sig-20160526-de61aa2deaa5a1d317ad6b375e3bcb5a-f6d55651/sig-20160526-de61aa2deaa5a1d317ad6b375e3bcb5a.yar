rule sig_20160526_de61aa2deaa5a1d317ad6b375e3bcb5a {
  meta:
    description = "datamaliciousorder - file 20160526_de61aa2deaa5a1d317ad6b375e3bcb5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aafdb58f59d57c49072b70316e8ee8e57d8aa0993bf0b1978961757c38834fd7"

  strings:
    $s1  = "function qHNrHcNR(HUmRsjMUabaPa) {var fLKhgWXxYxyj = AuKoUGxf.join(eLwtJKTQzmTMKNhJJHTQbSZT[0]);var itRioFhvSwPgpP, lwrzw, AAbAq" ascii
    $s2  = " - 1))-573)) OGJQndUqkZOhECQcJ += nAMMEsCewHvfoDol(itRioFhvSwPgpP, lwrzw);else OGJQndUqkZOhECQcJ += YnvXjKOuZsuVVOeEL(itRioFhvSw" ascii
    $s3  = "+= sj(itRioFhvSwPgpP);else if (diKSyExQayFTRLASLeM == (637 + Math.round((Math.pow(Math.sin(791), 2) + Math.pow(Math.cos(791), 2)" ascii
    $s4  = "function qCIJkeXWYVtzSItAZv(dhoPz,uEFFHVitH){return dhoPz.charAt(uEFFHVitH);}" fullword ascii
    $s5  = "function YnvXjKOuZsuVVOeEL(yxCGcRyBqDM,pkpFTGNbIniQOePXJb,yAJNUQFzCWUZXkWZIbncc){return String.fromCharCode(yxCGcRyBqDM,pkpFTGNb" ascii
    $s6  = "function YnvXjKOuZsuVVOeEL(yxCGcRyBqDM,pkpFTGNbIniQOePXJb,yAJNUQFzCWUZXkWZIbncc){return String.fromCharCode(yxCGcRyBqDM,pkpFTGNb" ascii
    $s7  = "function XrVfTuMMYhONfhke(EGffsZavqxyVtQU,ZRpxSRAXytZe){return EGffsZavqxyVtQU.indexOf(ZRpxSRAXytZe);}" fullword ascii
    $s8  = "function nAMMEsCewHvfoDol(ejjFUZPmBrPGcQgnwwDDtt,OfpgXBGC){return String.fromCharCode(ejjFUZPmBrPGcQgnwwDDtt,OfpgXBGC);}" fullword ascii
    $s9  = "function sj(TlUjqfUqltzRCqdssWmM){return String.fromCharCode(TlUjqfUqltzRCqdssWmM);}" fullword ascii
    $s10 = "function qHNrHcNR(HUmRsjMUabaPa) {var fLKhgWXxYxyj = AuKoUGxf.join(eLwtJKTQzmTMKNhJJHTQbSZT[0]);var itRioFhvSwPgpP, lwrzw, AAbAq" ascii
    $s11 = "PgpP, lwrzw, AAbAqnyxlEa);} while (GdRFI < HUmRsjMUabaPa.length);return OGJQndUqkZOhECQcJ;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}