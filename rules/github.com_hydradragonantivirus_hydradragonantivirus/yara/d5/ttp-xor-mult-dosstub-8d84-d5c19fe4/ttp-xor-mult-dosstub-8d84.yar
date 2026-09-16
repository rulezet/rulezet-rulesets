rule TTP_XOR_MULT_DOSStub_8d84 {
  strings:
    $key_8d84 = { d9 ec [2] ad f4 [2] ea f6 [2] ad e7 [2] e3 eb [2] ef e1 [2] f8 ea [2] e3 a4 [2] de }

  condition:
    any of them
}