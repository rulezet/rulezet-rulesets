rule TTP_XOR_MULT_DOSStub_8d38 {
  strings:
    $key_8d38 = { d9 50 [2] ad 48 [2] ea 4a [2] ad 5b [2] e3 57 [2] ef 5d [2] f8 56 [2] e3 18 [2] de }

  condition:
    any of them
}