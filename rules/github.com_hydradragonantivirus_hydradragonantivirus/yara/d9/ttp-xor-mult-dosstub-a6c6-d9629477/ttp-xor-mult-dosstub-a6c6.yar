rule TTP_XOR_MULT_DOSStub_a6c6 {
  strings:
    $key_a6c6 = { f2 ae [2] 86 b6 [2] c1 b4 [2] 86 a5 [2] c8 a9 [2] c4 a3 [2] d3 a8 [2] c8 e6 [2] f5 }

  condition:
    any of them
}