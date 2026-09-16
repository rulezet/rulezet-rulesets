rule TTP_XOR_MULT_DOSStub_c497 {
  strings:
    $key_c497 = { 90 ff [2] e4 e7 [2] a3 e5 [2] e4 f4 [2] aa f8 [2] a6 f2 [2] b1 f9 [2] aa b7 [2] 97 }

  condition:
    any of them
}