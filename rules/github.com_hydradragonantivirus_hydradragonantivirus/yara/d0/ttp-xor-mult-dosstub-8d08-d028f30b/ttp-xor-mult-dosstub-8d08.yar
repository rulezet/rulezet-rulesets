rule TTP_XOR_MULT_DOSStub_8d08 {
  strings:
    $key_8d08 = { d9 60 [2] ad 78 [2] ea 7a [2] ad 6b [2] e3 67 [2] ef 6d [2] f8 66 [2] e3 28 [2] de }

  condition:
    any of them
}