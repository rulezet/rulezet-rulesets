rule TTP_XOR_MULT_DOSStub_5819 {
  strings:
    $key_5819 = { 0c 71 [2] 78 69 [2] 3f 6b [2] 78 7a [2] 36 76 [2] 3a 7c [2] 2d 77 [2] 36 39 [2] 0b }

  condition:
    any of them
}