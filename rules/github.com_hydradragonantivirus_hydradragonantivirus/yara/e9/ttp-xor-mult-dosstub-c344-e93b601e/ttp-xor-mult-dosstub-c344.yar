rule TTP_XOR_MULT_DOSStub_c344 {
  strings:
    $key_c344 = { 97 2c [2] e3 34 [2] a4 36 [2] e3 27 [2] ad 2b [2] a1 21 [2] b6 2a [2] ad 64 [2] 90 }

  condition:
    any of them
}