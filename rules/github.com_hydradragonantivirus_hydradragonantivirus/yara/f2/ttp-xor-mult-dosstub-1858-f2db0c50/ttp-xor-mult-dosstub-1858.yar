rule TTP_XOR_MULT_DOSStub_1858 {
  strings:
    $key_1858 = { 4c 30 [2] 38 28 [2] 7f 2a [2] 38 3b [2] 76 37 [2] 7a 3d [2] 6d 36 [2] 76 78 [2] 4b }

  condition:
    any of them
}