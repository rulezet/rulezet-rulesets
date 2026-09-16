rule TTP_XOR_MULT_DOSStub_5356 {
  strings:
    $key_5356 = { 07 3e [2] 73 26 [2] 34 24 [2] 73 35 [2] 3d 39 [2] 31 33 [2] 26 38 [2] 3d 76 [2] 00 }

  condition:
    any of them
}