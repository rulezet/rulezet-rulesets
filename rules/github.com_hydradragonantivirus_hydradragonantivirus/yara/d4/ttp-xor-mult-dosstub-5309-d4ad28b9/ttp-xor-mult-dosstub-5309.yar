rule TTP_XOR_MULT_DOSStub_5309 {
  strings:
    $key_5309 = { 07 61 [2] 73 79 [2] 34 7b [2] 73 6a [2] 3d 66 [2] 31 6c [2] 26 67 [2] 3d 29 [2] 00 }

  condition:
    any of them
}