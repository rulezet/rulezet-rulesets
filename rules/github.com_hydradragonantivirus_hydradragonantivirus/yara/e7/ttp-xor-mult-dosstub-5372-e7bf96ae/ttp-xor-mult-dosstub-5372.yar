rule TTP_XOR_MULT_DOSStub_5372 {
  strings:
    $key_5372 = { 07 1a [2] 73 02 [2] 34 00 [2] 73 11 [2] 3d 1d [2] 31 17 [2] 26 1c [2] 3d 52 [2] 00 }

  condition:
    any of them
}