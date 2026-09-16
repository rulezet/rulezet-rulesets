rule TTP_XOR_MULT_DOSStub_5435 {
  strings:
    $key_5435 = { 00 5d [2] 74 45 [2] 33 47 [2] 74 56 [2] 3a 5a [2] 36 50 [2] 21 5b [2] 3a 15 [2] 07 }

  condition:
    any of them
}