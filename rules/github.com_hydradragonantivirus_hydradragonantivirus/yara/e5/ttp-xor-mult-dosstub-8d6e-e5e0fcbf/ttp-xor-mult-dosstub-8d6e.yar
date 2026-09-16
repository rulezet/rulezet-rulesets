rule TTP_XOR_MULT_DOSStub_8d6e {
  strings:
    $key_8d6e = { d9 06 [2] ad 1e [2] ea 1c [2] ad 0d [2] e3 01 [2] ef 0b [2] f8 00 [2] e3 4e [2] de }

  condition:
    any of them
}