rule TTP_XOR_MULT_DOSStub_b7b4 {
  strings:
    $key_b7b4 = { e3 dc [2] 97 c4 [2] d0 c6 [2] 97 d7 [2] d9 db [2] d5 d1 [2] c2 da [2] d9 94 [2] e4 }

  condition:
    any of them
}