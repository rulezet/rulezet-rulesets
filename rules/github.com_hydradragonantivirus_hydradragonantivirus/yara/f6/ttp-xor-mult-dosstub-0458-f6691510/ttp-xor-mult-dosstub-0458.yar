rule TTP_XOR_MULT_DOSStub_0458 {
  strings:
    $key_0458 = { 50 30 [2] 24 28 [2] 63 2a [2] 24 3b [2] 6a 37 [2] 66 3d [2] 71 36 [2] 6a 78 [2] 57 }

  condition:
    any of them
}