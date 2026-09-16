rule TTP_XOR_MULT_DOSStub_8df4 {
  strings:
    $key_8df4 = { d9 9c [2] ad 84 [2] ea 86 [2] ad 97 [2] e3 9b [2] ef 91 [2] f8 9a [2] e3 d4 [2] de }

  condition:
    any of them
}