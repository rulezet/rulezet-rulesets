rule TTP_XOR_MULT_DOSStub_8d15 {
  strings:
    $key_8d15 = { d9 7d [2] ad 65 [2] ea 67 [2] ad 76 [2] e3 7a [2] ef 70 [2] f8 7b [2] e3 35 [2] de }

  condition:
    any of them
}