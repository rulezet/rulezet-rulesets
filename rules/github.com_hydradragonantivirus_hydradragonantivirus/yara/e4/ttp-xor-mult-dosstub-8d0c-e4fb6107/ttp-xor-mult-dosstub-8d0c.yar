rule TTP_XOR_MULT_DOSStub_8d0c {
  strings:
    $key_8d0c = { d9 64 [2] ad 7c [2] ea 7e [2] ad 6f [2] e3 63 [2] ef 69 [2] f8 62 [2] e3 2c [2] de }

  condition:
    any of them
}