rule TTP_XOR_MULT_DOSStub_73f5 {
  strings:
    $key_73f5 = { 27 9d [2] 53 85 [2] 14 87 [2] 53 96 [2] 1d 9a [2] 11 90 [2] 06 9b [2] 1d d5 [2] 20 }

  condition:
    any of them
}