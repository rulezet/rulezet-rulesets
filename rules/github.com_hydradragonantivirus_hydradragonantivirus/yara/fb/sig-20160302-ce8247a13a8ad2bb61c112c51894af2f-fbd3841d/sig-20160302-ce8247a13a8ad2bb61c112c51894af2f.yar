rule sig_20160302_ce8247a13a8ad2bb61c112c51894af2f {
  meta:
    description = "datamaliciousorder - file 20160302_ce8247a13a8ad2bb61c112c51894af2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c06de37b6e74eedb23081a0c9890d81fdea353a3c062f2c0e9b5175e362e732"

  strings:
    $s1  = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s2  = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s3  = "            return u((t >>> 10) + 55296) + u((1023 & t) + 56320);" fullword ascii
    $s4  = "            return u(240 | e >>> 18 & 7) + u(128 | e >>> 12 & 63) + u(128 | e >>> 6 & 63) + u(128 | 63 & e);" fullword ascii
    $s5  = "        return WScript[e](r);" fullword ascii
    $s6  = "var stratumpgl = function() {" fullword ascii
    $s7  = "var grovelUKT = function(r) {" fullword ascii
    $s8  = "    var h = String[\"fro\" + \"mCh\" + \"ar\" + \"Code\"];" fullword ascii
    $s9  = "        VERSION: t," fullword ascii
    $s10 = "        decode: b," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}