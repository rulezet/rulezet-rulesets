rule TTP_XOR_MULT_DOSStub_5814 {
  strings:
    $key_5814 = { 0c 7c [2] 78 64 [2] 3f 66 [2] 78 77 [2] 36 7b [2] 3a 71 [2] 2d 7a [2] 36 34 [2] 0b }

  condition:
    any of them
}