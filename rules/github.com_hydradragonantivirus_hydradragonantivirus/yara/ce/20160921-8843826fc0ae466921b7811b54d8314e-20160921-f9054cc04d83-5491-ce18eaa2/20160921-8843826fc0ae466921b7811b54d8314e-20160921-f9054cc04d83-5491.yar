rule _20160921_8843826fc0ae466921b7811b54d8314e_20160921_f9054cc04d83_5491 {
  meta:
    description = "datamaliciousorder - from files 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Q" ascii
    $s2 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s3 = "{return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(" ascii
    $s4 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})" ascii
    $s5 = "(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}