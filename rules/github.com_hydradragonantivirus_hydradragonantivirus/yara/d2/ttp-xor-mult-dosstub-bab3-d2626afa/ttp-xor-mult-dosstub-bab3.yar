rule TTP_XOR_MULT_DOSStub_bab3 {
  strings:
    $key_bab3 = { ee db [2] 9a c3 [2] dd c1 [2] 9a d0 [2] d4 dc [2] d8 d6 [2] cf dd [2] d4 93 [2] e9 }

  condition:
    any of them
}