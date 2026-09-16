rule TTP_XOR_MULT_DOSStub_8d05 {
  strings:
    $key_8d05 = { d9 6d [2] ad 75 [2] ea 77 [2] ad 66 [2] e3 6a [2] ef 60 [2] f8 6b [2] e3 25 [2] de }

  condition:
    any of them
}