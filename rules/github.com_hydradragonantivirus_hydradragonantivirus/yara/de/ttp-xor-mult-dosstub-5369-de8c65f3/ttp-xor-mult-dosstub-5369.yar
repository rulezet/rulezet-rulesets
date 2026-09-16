rule TTP_XOR_MULT_DOSStub_5369 {
  strings:
    $key_5369 = { 07 01 [2] 73 19 [2] 34 1b [2] 73 0a [2] 3d 06 [2] 31 0c [2] 26 07 [2] 3d 49 [2] 00 }

  condition:
    any of them
}