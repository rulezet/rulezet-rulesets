rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_f9054cc04d83_3437 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";" ascii
    $s2 = " f000(){return \"Uo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s3 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(" ascii
    $s4 = "on f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s5 = "nction f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s6 = " \"YTp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}