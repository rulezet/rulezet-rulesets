rule TTP_XOR_MULT_DOSStub_2378 {
  strings:
    $key_2378 = { 77 10 [2] 03 08 [2] 44 0a [2] 03 1b [2] 4d 17 [2] 41 1d [2] 56 16 [2] 4d 58 [2] 70 }

  condition:
    any of them
}