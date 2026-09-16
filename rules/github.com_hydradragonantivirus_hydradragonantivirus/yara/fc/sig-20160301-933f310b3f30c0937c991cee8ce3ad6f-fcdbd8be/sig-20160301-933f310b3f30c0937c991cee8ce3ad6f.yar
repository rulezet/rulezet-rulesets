rule sig_20160301_933f310b3f30c0937c991cee8ce3ad6f {
  meta:
    description = "datamaliciousorder - file 20160301_933f310b3f30c0937c991cee8ce3ad6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "199f51ed3f1f1c3e7f6c2f69e6a52e262edeba5a7b69c8a40fb38bd42016a002"

  strings:
    $s1 = "while (paroleMoral[(\"\\u0072\\u0065\\u0063\\u006f\\u006d\\u006de\\u006e\\u0064\", \"r\\u0065\\u0061\\u0064y\\u0073tate\")] < ((" ascii
    $s2 = "operaTract[(\"in\\u0074e\\u0072n\\u0061\\u0074\\u0069\\u006fna\\u006c\", \"\\u0053\\u006ce\\u0065\\u0070\")](2 * (1 * 2) * (3 ^ " ascii
    $s3 = "directorResidence = ((71 + 30), this);" fullword ascii
    $s4 = "while (paroleMoral[(\"\\u0072\\u0065\\u0063\\u006f\\u006d\\u006de\\u006e\\u0064\", \"r\\u0065\\u0061\\u0064y\\u0073tate\")] < ((" ascii
    $s5 = "firmControl[(\"i\\u0064\\u0065\\u006e\\u0074\\u0069ca\\u006c\", function String.prototype.hierarchyOfficial() {" fullword ascii
    $s6 = "} catch (consultantAccent) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}