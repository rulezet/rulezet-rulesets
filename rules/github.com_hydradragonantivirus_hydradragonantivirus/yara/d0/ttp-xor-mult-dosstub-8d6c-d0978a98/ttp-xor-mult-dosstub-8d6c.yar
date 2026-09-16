rule TTP_XOR_MULT_DOSStub_8d6c {
  strings:
    $key_8d6c = { d9 04 [2] ad 1c [2] ea 1e [2] ad 0f [2] e3 03 [2] ef 09 [2] f8 02 [2] e3 4c [2] de }

  condition:
    any of them
}