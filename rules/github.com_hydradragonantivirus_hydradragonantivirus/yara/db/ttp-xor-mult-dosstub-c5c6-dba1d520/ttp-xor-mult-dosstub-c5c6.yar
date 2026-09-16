rule TTP_XOR_MULT_DOSStub_c5c6 {
  strings:
    $key_c5c6 = { 91 ae [2] e5 b6 [2] a2 b4 [2] e5 a5 [2] ab a9 [2] a7 a3 [2] b0 a8 [2] ab e6 [2] 96 }

  condition:
    any of them
}