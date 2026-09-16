rule TTP_XOR_MULT_DOSStub_2d55 {
  strings:
    $key_2d55 = { 79 3d [2] 0d 25 [2] 4a 27 [2] 0d 36 [2] 43 3a [2] 4f 30 [2] 58 3b [2] 43 75 [2] 7e }

  condition:
    any of them
}