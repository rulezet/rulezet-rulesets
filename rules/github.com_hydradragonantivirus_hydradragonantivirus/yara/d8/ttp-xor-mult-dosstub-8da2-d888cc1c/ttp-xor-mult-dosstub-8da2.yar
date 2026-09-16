rule TTP_XOR_MULT_DOSStub_8da2 {
  strings:
    $key_8da2 = { d9 ca [2] ad d2 [2] ea d0 [2] ad c1 [2] e3 cd [2] ef c7 [2] f8 cc [2] e3 82 [2] de }

  condition:
    any of them
}