rule TTP_XOR_MULT_DOSStub_8d7b {
  strings:
    $key_8d7b = { d9 13 [2] ad 0b [2] ea 09 [2] ad 18 [2] e3 14 [2] ef 1e [2] f8 15 [2] e3 5b [2] de }

  condition:
    any of them
}