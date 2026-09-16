rule sig_20160525_574d35dce452497e7087b378a5724f91 {
  meta:
    description = "datamaliciousorder - file 20160525_574d35dce452497e7087b378a5724f91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9a84ee390dfcc338b39072610353430164564130bef9e27488217ad350e34b5"

  strings:
    $s1 = "oda rav\\n;)))(};ssorcag nruter{)(tsilslianbmuhtog noitcnuf( + sdnetg(sgnirtStnemnorivnEdnapxE.dnenoisillocb = modnar rav\\n;)de" ascii
    $s2 = "darn + mn + dnenoisillocn[eixodb    \\n;))rerednera(m(]dnenoisillocu + suidarelcitrapu + ))(};gsmu nruter{)(mu noitcnuf([eixodb " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}