rule TTP_XOR_MULT_DOSStub_1263 {
  strings:
    $key_1263 = { 46 0b [2] 32 13 [2] 75 11 [2] 32 00 [2] 7c 0c [2] 70 06 [2] 67 0d [2] 7c 43 [2] 41 }

  condition:
    any of them
}