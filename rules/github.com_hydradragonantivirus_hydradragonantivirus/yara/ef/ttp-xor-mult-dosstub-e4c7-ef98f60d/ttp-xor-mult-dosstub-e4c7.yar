rule TTP_XOR_MULT_DOSStub_e4c7 {
  strings:
    $key_e4c7 = { b0 af [2] c4 b7 [2] 83 b5 [2] c4 a4 [2] 8a a8 [2] 86 a2 [2] 91 a9 [2] 8a e7 [2] b7 }

  condition:
    any of them
}