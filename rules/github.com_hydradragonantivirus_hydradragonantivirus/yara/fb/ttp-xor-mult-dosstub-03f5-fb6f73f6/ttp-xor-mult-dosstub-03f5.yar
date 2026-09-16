rule TTP_XOR_MULT_DOSStub_03f5 {
  strings:
    $key_03f5 = { 57 9d [2] 23 85 [2] 64 87 [2] 23 96 [2] 6d 9a [2] 61 90 [2] 76 9b [2] 6d d5 [2] 50 }

  condition:
    any of them
}