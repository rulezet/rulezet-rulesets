rule TTP_XOR_MULT_DOSStub_224a {
  strings:
    $key_224a = { 76 22 [2] 02 3a [2] 45 38 [2] 02 29 [2] 4c 25 [2] 40 2f [2] 57 24 [2] 4c 6a [2] 71 }

  condition:
    any of them
}