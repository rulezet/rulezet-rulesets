rule TTP_XOR_MULT_DOSStub_364a {
  strings:
    $key_364a = { 62 22 [2] 16 3a [2] 51 38 [2] 16 29 [2] 58 25 [2] 54 2f [2] 43 24 [2] 58 6a [2] 65 }

  condition:
    any of them
}