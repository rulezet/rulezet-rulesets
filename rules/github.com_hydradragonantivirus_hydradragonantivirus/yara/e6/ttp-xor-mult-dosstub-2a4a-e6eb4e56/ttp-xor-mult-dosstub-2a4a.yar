rule TTP_XOR_MULT_DOSStub_2a4a {
  strings:
    $key_2a4a = { 7e 22 [2] 0a 3a [2] 4d 38 [2] 0a 29 [2] 44 25 [2] 48 2f [2] 5f 24 [2] 44 6a [2] 79 }

  condition:
    any of them
}