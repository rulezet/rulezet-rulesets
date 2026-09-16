rule TTP_XOR_MULT_DOSStub_e1d6 {
  strings:
    $key_e1d6 = { b5 be [2] c1 a6 [2] 86 a4 [2] c1 b5 [2] 8f b9 [2] 83 b3 [2] 94 b8 [2] 8f f6 [2] b2 }

  condition:
    any of them
}