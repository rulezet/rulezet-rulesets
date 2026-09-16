rule TTP_XOR_MULT_DOSStub_c045 {
  strings:
    $key_c045 = { 94 2d [2] e0 35 [2] a7 37 [2] e0 26 [2] ae 2a [2] a2 20 [2] b5 2b [2] ae 65 [2] 93 }

  condition:
    any of them
}