rule TTP_XOR_MULT_DOSStub_d6c6 {
  strings:
    $key_d6c6 = { 82 ae [2] f6 b6 [2] b1 b4 [2] f6 a5 [2] b8 a9 [2] b4 a3 [2] a3 a8 [2] b8 e6 [2] 85 }

  condition:
    any of them
}