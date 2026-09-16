rule TTP_XOR_MULT_DOSStub_0452 {
  strings:
    $key_0452 = { 50 3a [2] 24 22 [2] 63 20 [2] 24 31 [2] 6a 3d [2] 66 37 [2] 71 3c [2] 6a 72 [2] 57 }

  condition:
    any of them
}