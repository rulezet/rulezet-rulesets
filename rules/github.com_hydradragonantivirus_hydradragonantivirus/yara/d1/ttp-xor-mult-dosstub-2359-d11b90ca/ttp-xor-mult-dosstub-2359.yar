rule TTP_XOR_MULT_DOSStub_2359 {
  strings:
    $key_2359 = { 77 31 [2] 03 29 [2] 44 2b [2] 03 3a [2] 4d 36 [2] 41 3c [2] 56 37 [2] 4d 79 [2] 70 }

  condition:
    any of them
}