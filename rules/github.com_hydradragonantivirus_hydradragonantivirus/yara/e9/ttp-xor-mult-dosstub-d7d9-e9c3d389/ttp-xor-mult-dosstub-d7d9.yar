rule TTP_XOR_MULT_DOSStub_d7d9 {
  strings:
    $key_d7d9 = { 83 b1 [2] f7 a9 [2] b0 ab [2] f7 ba [2] b9 b6 [2] b5 bc [2] a2 b7 [2] b9 f9 [2] 84 }

  condition:
    any of them
}