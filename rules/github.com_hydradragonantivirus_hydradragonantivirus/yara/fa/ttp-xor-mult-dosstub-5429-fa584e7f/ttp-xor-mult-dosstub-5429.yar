rule TTP_XOR_MULT_DOSStub_5429 {
  strings:
    $key_5429 = { 00 41 [2] 74 59 [2] 33 5b [2] 74 4a [2] 3a 46 [2] 36 4c [2] 21 47 [2] 3a 09 [2] 07 }

  condition:
    any of them
}