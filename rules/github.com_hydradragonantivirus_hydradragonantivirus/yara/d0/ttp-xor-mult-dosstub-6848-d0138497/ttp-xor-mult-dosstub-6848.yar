rule TTP_XOR_MULT_DOSStub_6848 {
  strings:
    $key_6848 = { 3c 20 [2] 48 38 [2] 0f 3a [2] 48 2b [2] 06 27 [2] 0a 2d [2] 1d 26 [2] 06 68 [2] 3b }

  condition:
    any of them
}