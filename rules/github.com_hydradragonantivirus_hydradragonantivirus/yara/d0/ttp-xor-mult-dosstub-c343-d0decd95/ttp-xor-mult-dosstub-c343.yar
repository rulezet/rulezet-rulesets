rule TTP_XOR_MULT_DOSStub_c343 {
  strings:
    $key_c343 = { 97 2b [2] e3 33 [2] a4 31 [2] e3 20 [2] ad 2c [2] a1 26 [2] b6 2d [2] ad 63 [2] 90 }

  condition:
    any of them
}