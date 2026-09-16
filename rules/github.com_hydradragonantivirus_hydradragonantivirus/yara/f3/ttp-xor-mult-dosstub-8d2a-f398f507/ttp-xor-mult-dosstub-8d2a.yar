rule TTP_XOR_MULT_DOSStub_8d2a {
  strings:
    $key_8d2a = { d9 42 [2] ad 5a [2] ea 58 [2] ad 49 [2] e3 45 [2] ef 4f [2] f8 44 [2] e3 0a [2] de }

  condition:
    any of them
}