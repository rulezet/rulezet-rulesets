rule TTP_XOR_MULT_DOSStub_8d62 {
  strings:
    $key_8d62 = { d9 0a [2] ad 12 [2] ea 10 [2] ad 01 [2] e3 0d [2] ef 07 [2] f8 0c [2] e3 42 [2] de }

  condition:
    any of them
}