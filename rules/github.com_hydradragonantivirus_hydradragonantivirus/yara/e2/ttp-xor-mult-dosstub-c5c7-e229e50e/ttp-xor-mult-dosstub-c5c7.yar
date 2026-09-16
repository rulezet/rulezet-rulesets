rule TTP_XOR_MULT_DOSStub_c5c7 {
  strings:
    $key_c5c7 = { 91 af [2] e5 b7 [2] a2 b5 [2] e5 a4 [2] ab a8 [2] a7 a2 [2] b0 a9 [2] ab e7 [2] 96 }

  condition:
    any of them
}