rule TTP_XOR_MULT_DOSStub_8dfb {
  strings:
    $key_8dfb = { d9 93 [2] ad 8b [2] ea 89 [2] ad 98 [2] e3 94 [2] ef 9e [2] f8 95 [2] e3 db [2] de }

  condition:
    any of them
}