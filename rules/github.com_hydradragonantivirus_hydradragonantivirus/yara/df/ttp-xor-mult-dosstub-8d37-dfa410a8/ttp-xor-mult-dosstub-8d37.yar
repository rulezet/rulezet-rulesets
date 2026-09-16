rule TTP_XOR_MULT_DOSStub_8d37 {
  strings:
    $key_8d37 = { d9 5f [2] ad 47 [2] ea 45 [2] ad 54 [2] e3 58 [2] ef 52 [2] f8 59 [2] e3 17 [2] de }

  condition:
    any of them
}