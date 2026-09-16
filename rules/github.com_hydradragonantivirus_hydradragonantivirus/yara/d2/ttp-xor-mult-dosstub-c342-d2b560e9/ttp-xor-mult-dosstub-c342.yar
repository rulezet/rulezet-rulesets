rule TTP_XOR_MULT_DOSStub_c342 {
  strings:
    $key_c342 = { 97 2a [2] e3 32 [2] a4 30 [2] e3 21 [2] ad 2d [2] a1 27 [2] b6 2c [2] ad 62 [2] 90 }

  condition:
    any of them
}