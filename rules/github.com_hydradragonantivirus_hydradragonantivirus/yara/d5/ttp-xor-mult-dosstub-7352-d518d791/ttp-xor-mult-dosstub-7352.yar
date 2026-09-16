rule TTP_XOR_MULT_DOSStub_7352 {
  strings:
    $key_7352 = { 27 3a [2] 53 22 [2] 14 20 [2] 53 31 [2] 1d 3d [2] 11 37 [2] 06 3c [2] 1d 72 [2] 20 }

  condition:
    any of them
}