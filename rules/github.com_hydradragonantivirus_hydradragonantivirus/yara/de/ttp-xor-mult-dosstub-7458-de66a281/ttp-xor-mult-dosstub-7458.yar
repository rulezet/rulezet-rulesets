rule TTP_XOR_MULT_DOSStub_7458 {
  strings:
    $key_7458 = { 20 30 [2] 54 28 [2] 13 2a [2] 54 3b [2] 1a 37 [2] 16 3d [2] 01 36 [2] 1a 78 [2] 27 }

  condition:
    any of them
}