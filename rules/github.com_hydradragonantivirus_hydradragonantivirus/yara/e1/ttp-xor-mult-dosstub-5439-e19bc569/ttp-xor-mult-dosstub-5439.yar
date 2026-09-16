rule TTP_XOR_MULT_DOSStub_5439 {
  strings:
    $key_5439 = { 00 51 [2] 74 49 [2] 33 4b [2] 74 5a [2] 3a 56 [2] 36 5c [2] 21 57 [2] 3a 19 [2] 07 }

  condition:
    any of them
}