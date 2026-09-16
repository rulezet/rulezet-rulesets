rule TTP_XOR_MULT_DOSStub_4255 {
  strings:
    $key_4255 = { 16 3d [2] 62 25 [2] 25 27 [2] 62 36 [2] 2c 3a [2] 20 30 [2] 37 3b [2] 2c 75 [2] 11 }

  condition:
    any of them
}