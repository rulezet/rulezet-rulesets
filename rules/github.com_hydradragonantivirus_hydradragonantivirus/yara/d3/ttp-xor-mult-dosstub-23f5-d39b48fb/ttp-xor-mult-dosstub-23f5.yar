rule TTP_XOR_MULT_DOSStub_23f5 {
  strings:
    $key_23f5 = { 77 9d [2] 03 85 [2] 44 87 [2] 03 96 [2] 4d 9a [2] 41 90 [2] 56 9b [2] 4d d5 [2] 70 }

  condition:
    any of them
}