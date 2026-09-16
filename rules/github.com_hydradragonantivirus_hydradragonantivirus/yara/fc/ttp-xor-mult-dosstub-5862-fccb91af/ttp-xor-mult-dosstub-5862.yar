rule TTP_XOR_MULT_DOSStub_5862 {
  strings:
    $key_5862 = { 0c 0a [2] 78 12 [2] 3f 10 [2] 78 01 [2] 36 0d [2] 3a 07 [2] 2d 0c [2] 36 42 [2] 0b }

  condition:
    any of them
}