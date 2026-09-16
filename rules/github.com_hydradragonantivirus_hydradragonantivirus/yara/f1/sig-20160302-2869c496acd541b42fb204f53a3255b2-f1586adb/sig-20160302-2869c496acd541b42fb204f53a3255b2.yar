rule sig_20160302_2869c496acd541b42fb204f53a3255b2 {
  meta:
    description = "datamaliciousorder - file 20160302_2869c496acd541b42fb204f53a3255b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d10f1f91f54d179efec4ba76349bf779b651ec1144acc9b1ecd31128833c972"

  strings:
    $s1 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s2 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s3 = "            return u(240 | t >>> 18 & 7) + u(128 | t >>> 12 & 63) + u(128 | t >>> 6 & 63) + u(128 | 63 & t);" fullword ascii
    $s4 = "            return u((e >>> 10) + 55296) + u((1023 & e) + 56320);" fullword ascii
    $s5 = "var onsetZQf = function(r) {" fullword ascii
    $s6 = "var malleablek9r = function() {" fullword ascii
    $s7 = "    var u = String[\"fro\" + \"m\" + \"Cha\" + \"rCode\"];" fullword ascii
    $s8 = "        decode: S," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}