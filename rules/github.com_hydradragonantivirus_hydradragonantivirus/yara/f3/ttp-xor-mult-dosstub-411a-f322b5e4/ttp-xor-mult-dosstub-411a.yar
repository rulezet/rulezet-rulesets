rule TTP_XOR_MULT_DOSStub_411a {
  strings:
    $key_411a = { 15 72 [2] 61 6a [2] 26 68 [2] 61 79 [2] 2f 75 [2] 23 7f [2] 34 74 [2] 2f 3a [2] 12 }

  condition:
    any of them
}