rule TTP_XOR_MULT_DOSStub_3369 {
  strings:
    $key_3369 = { 67 01 [2] 13 19 [2] 54 1b [2] 13 0a [2] 5d 06 [2] 51 0c [2] 46 07 [2] 5d 49 [2] 60 }

  condition:
    any of them
}