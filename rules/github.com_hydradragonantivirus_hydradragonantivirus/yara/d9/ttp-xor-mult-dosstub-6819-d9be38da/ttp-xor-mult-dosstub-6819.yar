rule TTP_XOR_MULT_DOSStub_6819 {
  strings:
    $key_6819 = { 3c 71 [2] 48 69 [2] 0f 6b [2] 48 7a [2] 06 76 [2] 0a 7c [2] 1d 77 [2] 06 39 [2] 3b }

  condition:
    any of them
}