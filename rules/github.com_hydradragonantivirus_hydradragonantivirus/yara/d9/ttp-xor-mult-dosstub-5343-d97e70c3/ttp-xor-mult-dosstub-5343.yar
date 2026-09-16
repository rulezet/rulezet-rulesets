rule TTP_XOR_MULT_DOSStub_5343 {
  strings:
    $key_5343 = { 07 2b [2] 73 33 [2] 34 31 [2] 73 20 [2] 3d 2c [2] 31 26 [2] 26 2d [2] 3d 63 [2] 00 }

  condition:
    any of them
}