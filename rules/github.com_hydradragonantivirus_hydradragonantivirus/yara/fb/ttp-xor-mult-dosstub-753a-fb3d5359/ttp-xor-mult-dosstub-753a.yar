rule TTP_XOR_MULT_DOSStub_753a {
  strings:
    $key_753a = { 21 52 [2] 55 4a [2] 12 48 [2] 55 59 [2] 1b 55 [2] 17 5f [2] 00 54 [2] 1b 1a [2] 26 }

  condition:
    any of them
}