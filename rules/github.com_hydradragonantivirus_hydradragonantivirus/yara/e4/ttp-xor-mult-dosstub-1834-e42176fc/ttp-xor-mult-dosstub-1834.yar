rule TTP_XOR_MULT_DOSStub_1834 {
  strings:
    $key_1834 = { 4c 5c [2] 38 44 [2] 7f 46 [2] 38 57 [2] 76 5b [2] 7a 51 [2] 6d 5a [2] 76 14 [2] 4b }

  condition:
    any of them
}