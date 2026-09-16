rule TTP_XOR_MULT_DOSStub_c345 {
  strings:
    $key_c345 = { 97 2d [2] e3 35 [2] a4 37 [2] e3 26 [2] ad 2a [2] a1 20 [2] b6 2b [2] ad 65 [2] 90 }

  condition:
    any of them
}