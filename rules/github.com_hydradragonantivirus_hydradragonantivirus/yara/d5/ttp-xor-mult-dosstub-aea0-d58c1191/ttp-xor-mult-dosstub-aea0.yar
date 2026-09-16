rule TTP_XOR_MULT_DOSStub_aea0 {
  strings:
    $key_aea0 = { fa c8 [2] 8e d0 [2] c9 d2 [2] 8e c3 [2] c0 cf [2] cc c5 [2] db ce [2] c0 80 [2] fd }

  condition:
    any of them
}