rule TTP_XOR_MULT_DOSStub_384a {
  strings:
    $key_384a = { 6c 22 [2] 18 3a [2] 5f 38 [2] 18 29 [2] 56 25 [2] 5a 2f [2] 4d 24 [2] 56 6a [2] 6b }

  condition:
    any of them
}