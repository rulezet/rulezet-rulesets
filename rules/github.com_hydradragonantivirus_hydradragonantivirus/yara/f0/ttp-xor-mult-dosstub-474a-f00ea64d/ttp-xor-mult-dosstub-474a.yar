rule TTP_XOR_MULT_DOSStub_474a {
  strings:
    $key_474a = { 13 22 [2] 67 3a [2] 20 38 [2] 67 29 [2] 29 25 [2] 25 2f [2] 32 24 [2] 29 6a [2] 14 }

  condition:
    any of them
}