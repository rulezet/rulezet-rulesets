rule TTP_XOR_MULT_DOSStub_8d39 {
  strings:
    $key_8d39 = { d9 51 [2] ad 49 [2] ea 4b [2] ad 5a [2] e3 56 [2] ef 5c [2] f8 57 [2] e3 19 [2] de }

  condition:
    any of them
}