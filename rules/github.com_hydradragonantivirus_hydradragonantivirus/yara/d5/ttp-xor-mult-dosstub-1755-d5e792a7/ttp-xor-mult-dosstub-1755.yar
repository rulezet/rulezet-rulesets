rule TTP_XOR_MULT_DOSStub_1755 {
  strings:
    $key_1755 = { 43 3d [2] 37 25 [2] 70 27 [2] 37 36 [2] 79 3a [2] 75 30 [2] 62 3b [2] 79 75 [2] 44 }

  condition:
    any of them
}