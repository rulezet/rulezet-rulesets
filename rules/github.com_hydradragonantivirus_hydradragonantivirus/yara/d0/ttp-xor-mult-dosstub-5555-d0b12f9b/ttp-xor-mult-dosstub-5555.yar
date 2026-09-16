rule TTP_XOR_MULT_DOSStub_5555 {
  strings:
    $key_5555 = { 01 3d [2] 75 25 [2] 32 27 [2] 75 36 [2] 3b 3a [2] 37 30 [2] 20 3b [2] 3b 75 [2] 06 }

  condition:
    any of them
}