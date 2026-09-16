rule TTP_XOR_MULT_DOSStub_4858 {
  strings:
    $key_4858 = { 1c 30 [2] 68 28 [2] 2f 2a [2] 68 3b [2] 26 37 [2] 2a 3d [2] 3d 36 [2] 26 78 [2] 1b }

  condition:
    any of them
}