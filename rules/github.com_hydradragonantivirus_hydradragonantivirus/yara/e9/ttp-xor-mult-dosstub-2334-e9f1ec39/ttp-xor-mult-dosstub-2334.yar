rule TTP_XOR_MULT_DOSStub_2334 {
  strings:
    $key_2334 = { 77 5c [2] 03 44 [2] 44 46 [2] 03 57 [2] 4d 5b [2] 41 51 [2] 56 5a [2] 4d 14 [2] 70 }

  condition:
    any of them
}