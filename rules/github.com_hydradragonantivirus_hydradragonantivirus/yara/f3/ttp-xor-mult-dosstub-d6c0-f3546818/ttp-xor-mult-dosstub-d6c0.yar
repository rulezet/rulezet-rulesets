rule TTP_XOR_MULT_DOSStub_d6c0 {
  strings:
    $key_d6c0 = { 82 a8 [2] f6 b0 [2] b1 b2 [2] f6 a3 [2] b8 af [2] b4 a5 [2] a3 ae [2] b8 e0 [2] 85 }

  condition:
    any of them
}