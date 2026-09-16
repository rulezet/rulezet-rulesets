rule TTP_XOR_MULT_DOSStub_5855 {
  strings:
    $key_5855 = { 0c 3d [2] 78 25 [2] 3f 27 [2] 78 36 [2] 36 3a [2] 3a 30 [2] 2d 3b [2] 36 75 [2] 0b }

  condition:
    any of them
}