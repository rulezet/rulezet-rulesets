rule TTP_XOR_MULT_DOSStub_2362 {
  strings:
    $key_2362 = { 77 0a [2] 03 12 [2] 44 10 [2] 03 01 [2] 4d 0d [2] 41 07 [2] 56 0c [2] 4d 42 [2] 70 }

  condition:
    any of them
}