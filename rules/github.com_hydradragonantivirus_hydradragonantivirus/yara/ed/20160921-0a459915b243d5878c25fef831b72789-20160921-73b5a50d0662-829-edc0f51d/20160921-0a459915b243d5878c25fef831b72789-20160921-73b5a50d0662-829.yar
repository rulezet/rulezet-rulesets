rule _20160921_0a459915b243d5878c25fef831b72789_20160921_73b5a50d0662_829 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_73b5a50d06622b8411077815f2717627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"

  strings:
    $s1  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){retu" ascii
    $s2  = "urn \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3  = "})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f00" ascii
    $s4  = "f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj" ascii
    $s5  = "){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";}" ascii
    $s6  = "{return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";}" ascii
    $s7  = "Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(functio" ascii
    $s8  = "\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s9  = "ction f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s10 = "(){return \"DYs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";}" ascii
    $s11 = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(" ascii
    $s12 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(" ascii
    $s13 = "on f000(){return \"DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s14 = "urn \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(f" ascii
    $s15 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function " ascii
    $s16 = "Eg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MMz\";})(),(functi" ascii
    $s17 = "t\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s18 = "(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s19 = "function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){re" ascii
    $s20 = "rn \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}