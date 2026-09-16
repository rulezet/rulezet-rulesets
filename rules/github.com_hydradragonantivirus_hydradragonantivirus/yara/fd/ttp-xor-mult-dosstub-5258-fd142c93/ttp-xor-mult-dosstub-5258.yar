rule TTP_XOR_MULT_DOSStub_5258 {
  strings:
    $key_5258 = { 06 30 [2] 72 28 [2] 35 2a [2] 72 3b [2] 3c 37 [2] 30 3d [2] 27 36 [2] 3c 78 [2] 01 }

  condition:
    any of them
}