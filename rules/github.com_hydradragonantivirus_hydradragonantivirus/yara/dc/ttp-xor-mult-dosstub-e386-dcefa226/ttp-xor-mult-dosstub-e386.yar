rule TTP_XOR_MULT_DOSStub_e386 {
  strings:
    $key_e386 = { b7 ee [2] c3 f6 [2] 84 f4 [2] c3 e5 [2] 8d e9 [2] 81 e3 [2] 96 e8 [2] 8d a6 [2] b0 }

  condition:
    any of them
}