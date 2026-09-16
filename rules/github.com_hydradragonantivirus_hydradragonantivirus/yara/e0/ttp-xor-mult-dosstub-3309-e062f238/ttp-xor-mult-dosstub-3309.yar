rule TTP_XOR_MULT_DOSStub_3309 {
  strings:
    $key_3309 = { 67 61 [2] 13 79 [2] 54 7b [2] 13 6a [2] 5d 66 [2] 51 6c [2] 46 67 [2] 5d 29 [2] 60 }

  condition:
    any of them
}