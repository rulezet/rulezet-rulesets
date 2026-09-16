rule TTP_XOR_MULT_DOSStub_8de3 {
  strings:
    $key_8de3 = { d9 8b [2] ad 93 [2] ea 91 [2] ad 80 [2] e3 8c [2] ef 86 [2] f8 8d [2] e3 c3 [2] de }

  condition:
    any of them
}