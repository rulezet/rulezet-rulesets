rule TTP_XOR_MULT_DOSStub_b7a4 {
  strings:
    $key_b7a4 = { e3 cc [2] 97 d4 [2] d0 d6 [2] 97 c7 [2] d9 cb [2] d5 c1 [2] c2 ca [2] d9 84 [2] e4 }

  condition:
    any of them
}