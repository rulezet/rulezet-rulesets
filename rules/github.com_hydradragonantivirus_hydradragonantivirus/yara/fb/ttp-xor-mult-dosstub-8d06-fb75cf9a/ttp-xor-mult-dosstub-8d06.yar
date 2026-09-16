rule TTP_XOR_MULT_DOSStub_8d06 {
  strings:
    $key_8d06 = { d9 6e [2] ad 76 [2] ea 74 [2] ad 65 [2] e3 69 [2] ef 63 [2] f8 68 [2] e3 26 [2] de }

  condition:
    any of them
}