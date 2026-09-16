rule TTP_XOR_MULT_DOSStub_8dfa {
  strings:
    $key_8dfa = { d9 92 [2] ad 8a [2] ea 88 [2] ad 99 [2] e3 95 [2] ef 9f [2] f8 94 [2] e3 da [2] de }

  condition:
    any of them
}