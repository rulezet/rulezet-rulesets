rule TTP_XOR_MULT_DOSStub_2308 {
  strings:
    $key_2308 = { 77 60 [2] 03 78 [2] 44 7a [2] 03 6b [2] 4d 67 [2] 41 6d [2] 56 66 [2] 4d 28 [2] 70 }

  condition:
    any of them
}