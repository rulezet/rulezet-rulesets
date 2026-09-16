rule TTP_XOR_MULT_DOSStub_547a {
  strings:
    $key_547a = { 00 12 [2] 74 0a [2] 33 08 [2] 74 19 [2] 3a 15 [2] 36 1f [2] 21 14 [2] 3a 5a [2] 07 }

  condition:
    any of them
}