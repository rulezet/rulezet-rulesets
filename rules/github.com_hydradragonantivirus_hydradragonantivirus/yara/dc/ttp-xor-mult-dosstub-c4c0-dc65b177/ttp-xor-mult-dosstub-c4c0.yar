rule TTP_XOR_MULT_DOSStub_c4c0 {
  strings:
    $key_c4c0 = { 90 a8 [2] e4 b0 [2] a3 b2 [2] e4 a3 [2] aa af [2] a6 a5 [2] b1 ae [2] aa e0 [2] 97 }

  condition:
    any of them
}