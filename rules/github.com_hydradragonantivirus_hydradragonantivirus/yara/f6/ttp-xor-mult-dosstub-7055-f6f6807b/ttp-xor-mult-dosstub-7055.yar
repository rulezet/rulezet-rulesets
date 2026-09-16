rule TTP_XOR_MULT_DOSStub_7055 {
  strings:
    $key_7055 = { 24 3d [2] 50 25 [2] 17 27 [2] 50 36 [2] 1e 3a [2] 12 30 [2] 05 3b [2] 1e 75 [2] 23 }

  condition:
    any of them
}