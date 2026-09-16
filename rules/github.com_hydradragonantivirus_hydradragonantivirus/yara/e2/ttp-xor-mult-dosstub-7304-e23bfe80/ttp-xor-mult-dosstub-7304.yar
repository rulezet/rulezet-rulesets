rule TTP_XOR_MULT_DOSStub_7304 {
  strings:
    $key_7304 = { 27 6c [2] 53 74 [2] 14 76 [2] 53 67 [2] 1d 6b [2] 11 61 [2] 06 6a [2] 1d 24 [2] 20 }

  condition:
    any of them
}