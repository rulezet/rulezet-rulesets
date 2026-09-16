rule TTP_XOR_MULT_DOSStub_8d86 {
  strings:
    $key_8d86 = { d9 ee [2] ad f6 [2] ea f4 [2] ad e5 [2] e3 e9 [2] ef e3 [2] f8 e8 [2] e3 a6 [2] de }

  condition:
    any of them
}