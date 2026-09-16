rule TTP_XOR_MULT_DOSStub_f1b4 {
  strings:
    $key_f1b4 = { a5 dc [2] d1 c4 [2] 96 c6 [2] d1 d7 [2] 9f db [2] 93 d1 [2] 84 da [2] 9f 94 [2] a2 }

  condition:
    any of them
}