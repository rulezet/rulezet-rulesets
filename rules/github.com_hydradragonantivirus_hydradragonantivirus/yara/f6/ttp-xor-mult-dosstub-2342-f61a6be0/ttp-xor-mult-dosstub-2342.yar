rule TTP_XOR_MULT_DOSStub_2342 {
  strings:
    $key_2342 = { 77 2a [2] 03 32 [2] 44 30 [2] 03 21 [2] 4d 2d [2] 41 27 [2] 56 2c [2] 4d 62 [2] 70 }

  condition:
    any of them
}