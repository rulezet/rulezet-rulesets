rule TTP_XOR_MULT_DOSStub_8d95 {
  strings:
    $key_8d95 = { d9 fd [2] ad e5 [2] ea e7 [2] ad f6 [2] e3 fa [2] ef f0 [2] f8 fb [2] e3 b5 [2] de }

  condition:
    any of them
}