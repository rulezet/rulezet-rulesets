rule TTP_XOR_MULT_DOSStub_bfa0 {
  strings:
    $key_bfa0 = { eb c8 [2] 9f d0 [2] d8 d2 [2] 9f c3 [2] d1 cf [2] dd c5 [2] ca ce [2] d1 80 [2] ec }

  condition:
    any of them
}