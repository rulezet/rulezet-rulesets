rule TTP_XOR_MULT_DOSStub_2349 {
  strings:
    $key_2349 = { 77 21 [2] 03 39 [2] 44 3b [2] 03 2a [2] 4d 26 [2] 41 2c [2] 56 27 [2] 4d 69 [2] 70 }

  condition:
    any of them
}