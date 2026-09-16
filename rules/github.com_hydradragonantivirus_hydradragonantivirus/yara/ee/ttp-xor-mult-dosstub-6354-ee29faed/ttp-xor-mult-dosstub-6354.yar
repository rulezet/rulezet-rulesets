rule TTP_XOR_MULT_DOSStub_6354 {
  strings:
    $key_6354 = { 37 3c [2] 43 24 [2] 04 26 [2] 43 37 [2] 0d 3b [2] 01 31 [2] 16 3a [2] 0d 74 [2] 30 }

  condition:
    any of them
}