rule TTP_XOR_MULT_DOSStub_f1d0 {
  strings:
    $key_f1d0 = { a5 b8 [2] d1 a0 [2] 96 a2 [2] d1 b3 [2] 9f bf [2] 93 b5 [2] 84 be [2] 9f f0 [2] a2 }

  condition:
    any of them
}