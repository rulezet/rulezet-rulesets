rule TTP_XOR_MULT_DOSStub_8d1a {
  strings:
    $key_8d1a = { d9 72 [2] ad 6a [2] ea 68 [2] ad 79 [2] e3 75 [2] ef 7f [2] f8 74 [2] e3 3a [2] de }

  condition:
    any of them
}