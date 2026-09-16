rule TTP_XOR_MULT_DOSStub_5358 {
  strings:
    $key_5358 = { 07 30 [2] 73 28 [2] 34 2a [2] 73 3b [2] 3d 37 [2] 31 3d [2] 26 36 [2] 3d 78 [2] 00 }

  condition:
    any of them
}