rule TTP_XOR_MULT_DOSStub_8df0 {
  strings:
    $key_8df0 = { d9 98 [2] ad 80 [2] ea 82 [2] ad 93 [2] e3 9f [2] ef 95 [2] f8 9e [2] e3 d0 [2] de }

  condition:
    any of them
}