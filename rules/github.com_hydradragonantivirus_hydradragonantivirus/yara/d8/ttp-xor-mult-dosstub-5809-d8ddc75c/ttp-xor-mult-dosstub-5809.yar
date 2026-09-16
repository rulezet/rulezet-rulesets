rule TTP_XOR_MULT_DOSStub_5809 {
  strings:
    $key_5809 = { 0c 61 [2] 78 79 [2] 3f 7b [2] 78 6a [2] 36 66 [2] 3a 6c [2] 2d 67 [2] 36 29 [2] 0b }

  condition:
    any of them
}