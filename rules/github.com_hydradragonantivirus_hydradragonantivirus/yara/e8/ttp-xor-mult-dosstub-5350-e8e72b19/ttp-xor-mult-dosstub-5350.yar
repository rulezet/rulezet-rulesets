rule TTP_XOR_MULT_DOSStub_5350 {
  strings:
    $key_5350 = { 07 38 [2] 73 20 [2] 34 22 [2] 73 33 [2] 3d 3f [2] 31 35 [2] 26 3e [2] 3d 70 [2] 00 }

  condition:
    any of them
}