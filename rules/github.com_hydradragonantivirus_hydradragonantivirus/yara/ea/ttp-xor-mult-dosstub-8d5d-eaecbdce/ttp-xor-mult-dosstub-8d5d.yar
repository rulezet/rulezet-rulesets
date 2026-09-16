rule TTP_XOR_MULT_DOSStub_8d5d {
  strings:
    $key_8d5d = { d9 35 [2] ad 2d [2] ea 2f [2] ad 3e [2] e3 32 [2] ef 38 [2] f8 33 [2] e3 7d [2] de }

  condition:
    any of them
}