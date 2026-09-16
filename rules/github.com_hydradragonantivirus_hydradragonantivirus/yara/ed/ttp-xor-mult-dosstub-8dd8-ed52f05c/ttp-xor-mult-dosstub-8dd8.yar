rule TTP_XOR_MULT_DOSStub_8dd8 {
  strings:
    $key_8dd8 = { d9 b0 [2] ad a8 [2] ea aa [2] ad bb [2] e3 b7 [2] ef bd [2] f8 b6 [2] e3 f8 [2] de }

  condition:
    any of them
}