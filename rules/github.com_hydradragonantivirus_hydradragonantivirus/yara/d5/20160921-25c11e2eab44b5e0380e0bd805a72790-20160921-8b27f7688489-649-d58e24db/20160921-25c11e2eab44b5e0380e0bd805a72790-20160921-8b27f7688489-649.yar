rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_8b27f7688489_649 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1  = " f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wh" ascii
    $s2  = ",(function f000(){return \"Lo\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Br\";})(),(function f000(){re" ascii
    $s3  = ";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s4  = "turn \"MMz\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return " ascii
    $s6  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(f" ascii
    $s7  = "eturn \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})()," ascii
    $s8  = "urn \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s9  = "0(){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm" ascii
    $s10 = "(){return \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(" ascii
    $s11 = "unction f000(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s12 = "{return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"WIj\";})()" ascii
    $s13 = ")(),(function f000(){return \"RVb\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(" ascii
    $s14 = "return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})()," ascii
    $s15 = "n f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"B" ascii
    $s16 = "tion f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return" ascii
    $s17 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu" ascii
    $s18 = "return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(" ascii
    $s19 = "urn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Mc\";})(),(f" ascii
    $s20 = "return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}