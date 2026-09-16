rule TTP_XOR_MULT_DOSStub_751a {
  strings:
    $key_751a = { 21 72 [2] 55 6a [2] 12 68 [2] 55 79 [2] 1b 75 [2] 17 7f [2] 00 74 [2] 1b 3a [2] 26 }

  condition:
    any of them
}