rule TTP_XOR_MULT_DOSStub_b6a9 {
  strings:
    $key_b6a9 = { e2 c1 [2] 96 d9 [2] d1 db [2] 96 ca [2] d8 c6 [2] d4 cc [2] c3 c7 [2] d8 89 [2] e5 }

  condition:
    any of them
}