rule TTP_XOR_MULT_DOSStub_8d48 {
  strings:
    $key_8d48 = { d9 20 [2] ad 38 [2] ea 3a [2] ad 2b [2] e3 27 [2] ef 2d [2] f8 26 [2] e3 68 [2] de }

  condition:
    any of them
}