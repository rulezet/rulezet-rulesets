rule TTP_XOR_MULT_DOSStub_5d34 {
  strings:
    $key_5d34 = { 09 5c [2] 7d 44 [2] 3a 46 [2] 7d 57 [2] 33 5b [2] 3f 51 [2] 28 5a [2] 33 14 [2] 0e }

  condition:
    any of them
}