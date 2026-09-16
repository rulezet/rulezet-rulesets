rule TTP_XOR_MULT_DOSStub_4a58 {
  strings:
    $key_4a58 = { 1e 30 [2] 6a 28 [2] 2d 2a [2] 6a 3b [2] 24 37 [2] 28 3d [2] 3f 36 [2] 24 78 [2] 19 }

  condition:
    any of them
}