rule TTP_XOR_MULT_DOSStub_8dff {
  strings:
    $key_8dff = { d9 97 [2] ad 8f [2] ea 8d [2] ad 9c [2] e3 90 [2] ef 9a [2] f8 91 [2] e3 df [2] de }

  condition:
    any of them
}