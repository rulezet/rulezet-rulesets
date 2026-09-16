rule TTP_XOR_MULT_DOSStub_e486 {
  strings:
    $key_e486 = { b0 ee [2] c4 f6 [2] 83 f4 [2] c4 e5 [2] 8a e9 [2] 86 e3 [2] 91 e8 [2] 8a a6 [2] b7 }

  condition:
    any of them
}