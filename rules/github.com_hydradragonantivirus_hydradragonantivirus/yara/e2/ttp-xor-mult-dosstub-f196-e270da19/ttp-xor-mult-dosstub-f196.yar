rule TTP_XOR_MULT_DOSStub_f196 {
  strings:
    $key_f196 = { a5 fe [2] d1 e6 [2] 96 e4 [2] d1 f5 [2] 9f f9 [2] 93 f3 [2] 84 f8 [2] 9f b6 [2] a2 }

  condition:
    any of them
}