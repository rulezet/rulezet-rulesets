rule TTP_XOR_MULT_DOSStub_0242 {
  strings:
    $key_0242 = { 56 2a [2] 22 32 [2] 65 30 [2] 22 21 [2] 6c 2d [2] 60 27 [2] 77 2c [2] 6c 62 [2] 51 }

  condition:
    any of them
}