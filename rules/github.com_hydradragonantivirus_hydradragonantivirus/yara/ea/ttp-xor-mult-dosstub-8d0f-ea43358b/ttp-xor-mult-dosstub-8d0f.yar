rule TTP_XOR_MULT_DOSStub_8d0f {
  strings:
    $key_8d0f = { d9 67 [2] ad 7f [2] ea 7d [2] ad 6c [2] e3 60 [2] ef 6a [2] f8 61 [2] e3 2f [2] de }

  condition:
    any of them
}