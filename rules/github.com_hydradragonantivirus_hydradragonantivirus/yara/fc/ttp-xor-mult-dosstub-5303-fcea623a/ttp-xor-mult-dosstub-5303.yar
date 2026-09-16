rule TTP_XOR_MULT_DOSStub_5303 {
  strings:
    $key_5303 = { 07 6b [2] 73 73 [2] 34 71 [2] 73 60 [2] 3d 6c [2] 31 66 [2] 26 6d [2] 3d 23 [2] 00 }

  condition:
    any of them
}