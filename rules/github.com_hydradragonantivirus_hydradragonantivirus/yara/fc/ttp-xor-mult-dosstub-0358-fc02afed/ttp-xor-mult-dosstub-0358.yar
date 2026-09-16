rule TTP_XOR_MULT_DOSStub_0358 {
  strings:
    $key_0358 = { 57 30 [2] 23 28 [2] 64 2a [2] 23 3b [2] 6d 37 [2] 61 3d [2] 76 36 [2] 6d 78 [2] 50 }

  condition:
    any of them
}