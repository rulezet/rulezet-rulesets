rule _20160921_8b27f7688489936aa1cc7fded52f4a64_20160921_cdeac57ac549_3971 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s2 = "){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";}" ascii
    $s3 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})" ascii
    $s4 = "000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj" ascii
    $s5 = " f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv" ascii
    $s6 = "000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}