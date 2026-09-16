rule TTP_XOR_MULT_DOSStub_5349 {
  strings:
    $key_5349 = { 07 21 [2] 73 39 [2] 34 3b [2] 73 2a [2] 3d 26 [2] 31 2c [2] 26 27 [2] 3d 69 [2] 00 }

  condition:
    any of them
}