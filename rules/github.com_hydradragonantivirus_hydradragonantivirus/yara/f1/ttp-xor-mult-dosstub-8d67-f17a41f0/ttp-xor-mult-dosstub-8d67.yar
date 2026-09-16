rule TTP_XOR_MULT_DOSStub_8d67 {
  strings:
    $key_8d67 = { d9 0f [2] ad 17 [2] ea 15 [2] ad 04 [2] e3 08 [2] ef 02 [2] f8 09 [2] e3 47 [2] de }

  condition:
    any of them
}