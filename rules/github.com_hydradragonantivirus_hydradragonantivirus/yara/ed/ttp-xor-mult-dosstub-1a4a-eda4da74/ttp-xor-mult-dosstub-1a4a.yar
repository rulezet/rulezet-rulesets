rule TTP_XOR_MULT_DOSStub_1a4a {
  strings:
    $key_1a4a = { 4e 22 [2] 3a 3a [2] 7d 38 [2] 3a 29 [2] 74 25 [2] 78 2f [2] 6f 24 [2] 74 6a [2] 49 }

  condition:
    any of them
}