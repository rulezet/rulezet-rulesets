rule TTP_XOR_MULT_DOSStub_b3a4 {
  strings:
    $key_b3a4 = { e7 cc [2] 93 d4 [2] d4 d6 [2] 93 c7 [2] dd cb [2] d1 c1 [2] c6 ca [2] dd 84 [2] e0 }

  condition:
    any of them
}