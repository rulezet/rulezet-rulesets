rule TTP_XOR_MULT_DOSStub_3558 {
  strings:
    $key_3558 = { 61 30 [2] 15 28 [2] 52 2a [2] 15 3b [2] 5b 37 [2] 57 3d [2] 40 36 [2] 5b 78 [2] 66 }

  condition:
    any of them
}