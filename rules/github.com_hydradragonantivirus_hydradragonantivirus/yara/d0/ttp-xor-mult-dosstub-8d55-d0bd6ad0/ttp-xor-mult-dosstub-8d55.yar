rule TTP_XOR_MULT_DOSStub_8d55 {
  strings:
    $key_8d55 = { d9 3d [2] ad 25 [2] ea 27 [2] ad 36 [2] e3 3a [2] ef 30 [2] f8 3b [2] e3 75 [2] de }

  condition:
    any of them
}