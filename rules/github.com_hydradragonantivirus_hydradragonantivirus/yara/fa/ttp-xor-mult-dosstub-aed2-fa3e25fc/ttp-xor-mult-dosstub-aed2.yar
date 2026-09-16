rule TTP_XOR_MULT_DOSStub_aed2 {
  strings:
    $key_aed2 = { fa ba [2] 8e a2 [2] c9 a0 [2] 8e b1 [2] c0 bd [2] cc b7 [2] db bc [2] c0 f2 [2] fd }

  condition:
    any of them
}