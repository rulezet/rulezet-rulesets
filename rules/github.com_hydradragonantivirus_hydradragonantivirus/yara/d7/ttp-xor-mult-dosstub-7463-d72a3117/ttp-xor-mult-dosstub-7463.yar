rule TTP_XOR_MULT_DOSStub_7463 {
  strings:
    $key_7463 = { 20 0b [2] 54 13 [2] 13 11 [2] 54 00 [2] 1a 0c [2] 16 06 [2] 01 0d [2] 1a 43 [2] 27 }

  condition:
    any of them
}