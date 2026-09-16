rule TTP_XOR_MULT_DOSStub_1558 {
  strings:
    $key_1558 = { 41 30 [2] 35 28 [2] 72 2a [2] 35 3b [2] 7b 37 [2] 77 3d [2] 60 36 [2] 7b 78 [2] 46 }

  condition:
    any of them
}