rule TTP_XOR_MULT_DOSStub_8d12 {
  strings:
    $key_8d12 = { d9 7a [2] ad 62 [2] ea 60 [2] ad 71 [2] e3 7d [2] ef 77 [2] f8 7c [2] e3 32 [2] de }

  condition:
    any of them
}