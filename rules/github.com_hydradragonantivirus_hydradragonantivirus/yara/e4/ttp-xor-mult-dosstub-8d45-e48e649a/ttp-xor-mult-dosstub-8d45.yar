rule TTP_XOR_MULT_DOSStub_8d45 {
  strings:
    $key_8d45 = { d9 2d [2] ad 35 [2] ea 37 [2] ad 26 [2] e3 2a [2] ef 20 [2] f8 2b [2] e3 65 [2] de }

  condition:
    any of them
}