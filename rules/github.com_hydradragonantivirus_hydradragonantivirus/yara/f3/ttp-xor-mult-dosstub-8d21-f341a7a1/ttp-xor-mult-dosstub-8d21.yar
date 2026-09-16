rule TTP_XOR_MULT_DOSStub_8d21 {
  strings:
    $key_8d21 = { d9 49 [2] ad 51 [2] ea 53 [2] ad 42 [2] e3 4e [2] ef 44 [2] f8 4f [2] e3 01 [2] de }

  condition:
    any of them
}