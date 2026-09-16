rule TTP_XOR_MULT_DOSStub_5377 {
  strings:
    $key_5377 = { 07 1f [2] 73 07 [2] 34 05 [2] 73 14 [2] 3d 18 [2] 31 12 [2] 26 19 [2] 3d 57 [2] 00 }

  condition:
    any of them
}