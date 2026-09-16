rule TTP_XOR_MULT_DOSStub_4848 {
  strings:
    $key_4848 = { 1c 20 [2] 68 38 [2] 2f 3a [2] 68 2b [2] 26 27 [2] 2a 2d [2] 3d 26 [2] 26 68 [2] 1b }

  condition:
    any of them
}