rule TTP_XOR_MULT_DOSStub_1255 {
  strings:
    $key_1255 = { 46 3d [2] 32 25 [2] 75 27 [2] 32 36 [2] 7c 3a [2] 70 30 [2] 67 3b [2] 7c 75 [2] 41 }

  condition:
    any of them
}