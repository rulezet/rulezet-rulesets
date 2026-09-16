rule TTP_XOR_MULT_DOSStub_8dc3 {
  strings:
    $key_8dc3 = { d9 ab [2] ad b3 [2] ea b1 [2] ad a0 [2] e3 ac [2] ef a6 [2] f8 ad [2] e3 e3 [2] de }

  condition:
    any of them
}