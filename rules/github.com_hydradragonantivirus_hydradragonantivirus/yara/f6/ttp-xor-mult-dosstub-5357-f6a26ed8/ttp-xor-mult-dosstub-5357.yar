rule TTP_XOR_MULT_DOSStub_5357 {
  strings:
    $key_5357 = { 07 3f [2] 73 27 [2] 34 25 [2] 73 34 [2] 3d 38 [2] 31 32 [2] 26 39 [2] 3d 77 [2] 00 }

  condition:
    any of them
}