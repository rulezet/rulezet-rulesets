rule TTP_XOR_MULT_DOSStub_0055 {
  strings:
    $key_0055 = { 54 3d [2] 20 25 [2] 67 27 [2] 20 36 [2] 6e 3a [2] 62 30 [2] 75 3b [2] 6e 75 [2] 53 }

  condition:
    any of them
}