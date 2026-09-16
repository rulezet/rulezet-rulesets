rule _20160921_0a459915b243d5878c25fef831b72789_20160921_ded524cdc972_4328 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s2 = "(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";}" ascii
    $s3 = "000(){return \"HJm\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MD" ascii
    $s4 = "){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})" ascii
    $s5 = "urn \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}