rule TTP_XOR_MULT_DOSStub_8de8 {
  strings:
    $key_8de8 = { d9 80 [2] ad 98 [2] ea 9a [2] ad 8b [2] e3 87 [2] ef 8d [2] f8 86 [2] e3 c8 [2] de }

  condition:
    any of them
}