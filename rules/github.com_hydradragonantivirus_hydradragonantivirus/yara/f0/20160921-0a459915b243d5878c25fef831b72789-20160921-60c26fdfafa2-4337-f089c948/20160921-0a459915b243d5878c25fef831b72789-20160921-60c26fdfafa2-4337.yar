rule _20160921_0a459915b243d5878c25fef831b72789_20160921_60c26fdfafa2_4337 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_60c26fdfafa2666b92246aea46e32175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"

  strings:
    $s1 = "\"Km\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s2 = "on f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s3 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DNa\";})()" ascii
    $s4 = "n f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s5 = ")(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}