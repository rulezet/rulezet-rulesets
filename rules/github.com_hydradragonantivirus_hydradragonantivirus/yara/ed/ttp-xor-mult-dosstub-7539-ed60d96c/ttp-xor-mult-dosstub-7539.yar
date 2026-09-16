rule TTP_XOR_MULT_DOSStub_7539 {
  strings:
    $key_7539 = { 21 51 [2] 55 49 [2] 12 4b [2] 55 5a [2] 1b 56 [2] 17 5c [2] 00 57 [2] 1b 19 [2] 26 }

  condition:
    any of them
}