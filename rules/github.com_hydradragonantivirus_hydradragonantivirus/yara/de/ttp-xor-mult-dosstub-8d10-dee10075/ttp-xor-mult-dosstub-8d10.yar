rule TTP_XOR_MULT_DOSStub_8d10 {
  strings:
    $key_8d10 = { d9 78 [2] ad 60 [2] ea 62 [2] ad 73 [2] e3 7f [2] ef 75 [2] f8 7e [2] e3 30 [2] de }

  condition:
    any of them
}