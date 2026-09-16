rule TTP_XOR_MULT_DOSStub_5a55 {
  strings:
    $key_5a55 = { 0e 3d [2] 7a 25 [2] 3d 27 [2] 7a 36 [2] 34 3a [2] 38 30 [2] 2f 3b [2] 34 75 [2] 09 }

  condition:
    any of them
}