rule TTP_XOR_MULT_DOSStub_2343 {
  strings:
    $key_2343 = { 77 2b [2] 03 33 [2] 44 31 [2] 03 20 [2] 4d 2c [2] 41 26 [2] 56 2d [2] 4d 63 [2] 70 }

  condition:
    any of them
}