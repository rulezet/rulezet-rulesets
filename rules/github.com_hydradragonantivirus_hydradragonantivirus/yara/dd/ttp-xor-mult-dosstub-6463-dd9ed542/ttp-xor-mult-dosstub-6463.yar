rule TTP_XOR_MULT_DOSStub_6463 {
  strings:
    $key_6463 = { 30 0b [2] 44 13 [2] 03 11 [2] 44 00 [2] 0a 0c [2] 06 06 [2] 11 0d [2] 0a 43 [2] 37 }

  condition:
    any of them
}