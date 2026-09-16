rule TTP_XOR_MULT_DOSStub_1258 {
  strings:
    $key_1258 = { 46 30 [2] 32 28 [2] 75 2a [2] 32 3b [2] 7c 37 [2] 70 3d [2] 67 36 [2] 7c 78 [2] 41 }

  condition:
    any of them
}