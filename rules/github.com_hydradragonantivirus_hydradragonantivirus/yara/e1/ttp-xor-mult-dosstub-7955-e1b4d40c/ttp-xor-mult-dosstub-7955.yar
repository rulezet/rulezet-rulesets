rule TTP_XOR_MULT_DOSStub_7955 {
  strings:
    $key_7955 = { 2d 3d [2] 59 25 [2] 1e 27 [2] 59 36 [2] 17 3a [2] 1b 30 [2] 0c 3b [2] 17 75 [2] 2a }

  condition:
    any of them
}