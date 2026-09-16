rule TTP_XOR_MULT_DOSStub_5363 {
  strings:
    $key_5363 = { 07 0b [2] 73 13 [2] 34 11 [2] 73 00 [2] 3d 0c [2] 31 06 [2] 26 0d [2] 3d 43 [2] 00 }

  condition:
    any of them
}