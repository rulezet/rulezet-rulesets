rule TTP_XOR_MULT_DOSStub_3352 {
  strings:
    $key_3352 = { 67 3a [2] 13 22 [2] 54 20 [2] 13 31 [2] 5d 3d [2] 51 37 [2] 46 3c [2] 5d 72 [2] 60 }

  condition:
    any of them
}