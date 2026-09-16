rule _20160921_8b27f7688489936aa1cc7fded52f4a64_20160921_b32c8921e339_3086 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"K" ascii
    $s2 = ")(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s3 = "){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";" ascii
    $s4 = "on f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s5 = "000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut" ascii
    $s6 = ",(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){" ascii
    $s7 = "\"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}