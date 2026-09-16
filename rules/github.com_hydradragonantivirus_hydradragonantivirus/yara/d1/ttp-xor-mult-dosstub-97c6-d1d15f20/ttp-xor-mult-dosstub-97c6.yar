rule TTP_XOR_MULT_DOSStub_97c6 {
  strings:
    $key_97c6 = { c3 ae [2] b7 b6 [2] f0 b4 [2] b7 a5 [2] f9 a9 [2] f5 a3 [2] e2 a8 [2] f9 e6 [2] c4 }

  condition:
    any of them
}