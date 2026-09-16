rule TTP_XOR_MULT_DOSStub_5858 {
  strings:
    $key_5858 = { 0c 30 [2] 78 28 [2] 3f 2a [2] 78 3b [2] 36 37 [2] 3a 3d [2] 2d 36 [2] 36 78 [2] 0b }

  condition:
    any of them
}