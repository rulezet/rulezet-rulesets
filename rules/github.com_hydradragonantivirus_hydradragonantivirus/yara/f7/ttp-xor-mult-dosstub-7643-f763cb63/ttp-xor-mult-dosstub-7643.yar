rule TTP_XOR_MULT_DOSStub_7643 {
  strings:
    $key_7643 = { 22 2b [2] 56 33 [2] 11 31 [2] 56 20 [2] 18 2c [2] 14 26 [2] 03 2d [2] 18 63 [2] 25 }

  condition:
    any of them
}