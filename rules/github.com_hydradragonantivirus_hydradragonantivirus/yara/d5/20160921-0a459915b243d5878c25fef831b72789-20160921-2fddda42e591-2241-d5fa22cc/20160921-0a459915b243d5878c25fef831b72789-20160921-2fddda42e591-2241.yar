rule _20160921_0a459915b243d5878c25fef831b72789_20160921_2fddda42e591_2241 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_2fddda42e5911e6501568e734d430149.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"

  strings:
    $s1 = "function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(function f000(){ret" ascii
    $s2 = "i\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s3 = "{return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";}" ascii
    $s4 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s5 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retu" ascii
    $s6 = "turn \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s7 = "(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";}" ascii
    $s8 = ",(function f000(){return \"IPu\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DIa\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}