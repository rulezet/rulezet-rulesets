rule TTP_XOR_MULT_DOSStub_1358 {
  strings:
    $key_1358 = { 47 30 [2] 33 28 [2] 74 2a [2] 33 3b [2] 7d 37 [2] 71 3d [2] 66 36 [2] 7d 78 [2] 40 }

  condition:
    any of them
}