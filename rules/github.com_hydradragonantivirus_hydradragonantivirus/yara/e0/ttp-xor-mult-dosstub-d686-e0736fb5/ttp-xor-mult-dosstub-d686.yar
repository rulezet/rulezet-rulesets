rule TTP_XOR_MULT_DOSStub_d686 {
  strings:
    $key_d686 = { 82 ee [2] f6 f6 [2] b1 f4 [2] f6 e5 [2] b8 e9 [2] b4 e3 [2] a3 e8 [2] b8 a6 [2] 85 }

  condition:
    any of them
}