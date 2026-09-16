rule TTP_XOR_MULT_DOSStub_c042 {
  strings:
    $key_c042 = { 94 2a [2] e0 32 [2] a7 30 [2] e0 21 [2] ae 2d [2] a2 27 [2] b5 2c [2] ae 62 [2] 93 }

  condition:
    any of them
}