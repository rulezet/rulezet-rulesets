rule TTP_XOR_MULT_DOSStub_c4c6 {
  strings:
    $key_c4c6 = { 90 ae [2] e4 b6 [2] a3 b4 [2] e4 a5 [2] aa a9 [2] a6 a3 [2] b1 a8 [2] aa e6 [2] 97 }

  condition:
    any of them
}