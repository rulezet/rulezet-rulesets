rule TTP_XOR_MULT_DOSStub_5317 {
  strings:
    $key_5317 = { 07 7f [2] 73 67 [2] 34 65 [2] 73 74 [2] 3d 78 [2] 31 72 [2] 26 79 [2] 3d 37 [2] 00 }

  condition:
    any of them
}