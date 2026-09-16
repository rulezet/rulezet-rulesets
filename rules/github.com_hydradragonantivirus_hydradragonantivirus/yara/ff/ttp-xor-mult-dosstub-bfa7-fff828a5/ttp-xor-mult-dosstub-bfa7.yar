rule TTP_XOR_MULT_DOSStub_bfa7 {
  strings:
    $key_bfa7 = { eb cf [2] 9f d7 [2] d8 d5 [2] 9f c4 [2] d1 c8 [2] dd c2 [2] ca c9 [2] d1 87 [2] ec }

  condition:
    any of them
}