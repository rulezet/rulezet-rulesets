rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_b2002e7f99c6_1898 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash3       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"

  strings:
    $s1  = "urn \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s2  = " f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3  = "(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s4  = "ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(functi" ascii
    $s5  = "000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa" ascii
    $s6  = " f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Z" ascii
    $s7  = "(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s8  = " \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s9  = "urn \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})()," ascii
    $s10 = "on f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}