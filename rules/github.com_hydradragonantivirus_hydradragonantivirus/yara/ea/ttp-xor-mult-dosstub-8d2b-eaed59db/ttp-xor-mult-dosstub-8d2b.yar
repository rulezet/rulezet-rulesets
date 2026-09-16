rule TTP_XOR_MULT_DOSStub_8d2b {
  strings:
    $key_8d2b = { d9 43 [2] ad 5b [2] ea 59 [2] ad 48 [2] e3 44 [2] ef 4e [2] f8 45 [2] e3 0b [2] de }

  condition:
    any of them
}