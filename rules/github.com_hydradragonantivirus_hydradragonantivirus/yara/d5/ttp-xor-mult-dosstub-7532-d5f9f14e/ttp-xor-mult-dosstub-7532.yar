rule TTP_XOR_MULT_DOSStub_7532 {
  strings:
    $key_7532 = { 21 5a [2] 55 42 [2] 12 40 [2] 55 51 [2] 1b 5d [2] 17 57 [2] 00 5c [2] 1b 12 [2] 26 }

  condition:
    any of them
}