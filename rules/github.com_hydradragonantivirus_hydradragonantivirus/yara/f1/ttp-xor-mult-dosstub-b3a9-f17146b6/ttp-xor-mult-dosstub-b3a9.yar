rule TTP_XOR_MULT_DOSStub_b3a9 {
  strings:
    $key_b3a9 = { e7 c1 [2] 93 d9 [2] d4 db [2] 93 ca [2] dd c6 [2] d1 cc [2] c6 c7 [2] dd 89 [2] e0 }

  condition:
    any of them
}