rule TTP_XOR_MULT_DOSStub_c745 {
  strings:
    $key_c745 = { 93 2d [2] e7 35 [2] a0 37 [2] e7 26 [2] a9 2a [2] a5 20 [2] b2 2b [2] a9 65 [2] 94 }

  condition:
    any of them
}