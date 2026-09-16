rule TTP_XOR_MULT_DOSStub_5048 {
  strings:
    $key_5048 = { 04 20 [2] 70 38 [2] 37 3a [2] 70 2b [2] 3e 27 [2] 32 2d [2] 25 26 [2] 3e 68 [2] 03 }

  condition:
    any of them
}