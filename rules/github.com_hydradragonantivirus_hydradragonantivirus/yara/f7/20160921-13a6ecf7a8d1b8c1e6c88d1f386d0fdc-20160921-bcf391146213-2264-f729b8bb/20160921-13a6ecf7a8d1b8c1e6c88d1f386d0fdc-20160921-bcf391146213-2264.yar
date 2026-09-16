rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_bcf391146213_2264 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_bcf3911462135150c96c6b8eccf51628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"

  strings:
    $s1 = "nction f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s2 = "urn \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = "){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";" ascii
    $s4 = "eturn \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})()," ascii
    $s5 = "(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s6 = "function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"EZu\";})(),(function f000(){re" ascii
    $s7 = "urn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(" ascii
    $s8 = "n \"DNa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}