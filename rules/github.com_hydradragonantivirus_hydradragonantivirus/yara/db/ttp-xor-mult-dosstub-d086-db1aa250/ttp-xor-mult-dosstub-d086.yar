rule TTP_XOR_MULT_DOSStub_d086 {
  strings:
    $key_d086 = { 84 ee [2] f0 f6 [2] b7 f4 [2] f0 e5 [2] be e9 [2] b2 e3 [2] a5 e8 [2] be a6 [2] 83 }

  condition:
    any of them
}