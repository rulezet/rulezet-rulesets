rule TTP_XOR_MULT_DOSStub_8d80 {
  strings:
    $key_8d80 = { d9 e8 [2] ad f0 [2] ea f2 [2] ad e3 [2] e3 ef [2] ef e5 [2] f8 ee [2] e3 a0 [2] de }

  condition:
    any of them
}