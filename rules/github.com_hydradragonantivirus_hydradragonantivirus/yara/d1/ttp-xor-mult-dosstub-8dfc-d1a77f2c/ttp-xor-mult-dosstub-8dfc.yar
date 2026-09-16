rule TTP_XOR_MULT_DOSStub_8dfc {
  strings:
    $key_8dfc = { d9 94 [2] ad 8c [2] ea 8e [2] ad 9f [2] e3 93 [2] ef 99 [2] f8 92 [2] e3 dc [2] de }

  condition:
    any of them
}