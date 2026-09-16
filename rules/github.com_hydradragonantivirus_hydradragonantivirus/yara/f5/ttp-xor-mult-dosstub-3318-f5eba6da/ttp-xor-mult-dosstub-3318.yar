rule TTP_XOR_MULT_DOSStub_3318 {
  strings:
    $key_3318 = { 67 70 [2] 13 68 [2] 54 6a [2] 13 7b [2] 5d 77 [2] 51 7d [2] 46 76 [2] 5d 38 [2] 60 }

  condition:
    any of them
}