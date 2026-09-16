rule TTP_XOR_MULT_DOSStub_c4d6 {
  strings:
    $key_c4d6 = { 90 be [2] e4 a6 [2] a3 a4 [2] e4 b5 [2] aa b9 [2] a6 b3 [2] b1 b8 [2] aa f6 [2] 97 }

  condition:
    any of them
}