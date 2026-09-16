rule TTP_XOR_MULT_DOSStub_7958 {
  strings:
    $key_7958 = { 2d 30 [2] 59 28 [2] 1e 2a [2] 59 3b [2] 17 37 [2] 1b 3d [2] 0c 36 [2] 17 78 [2] 2a }

  condition:
    any of them
}