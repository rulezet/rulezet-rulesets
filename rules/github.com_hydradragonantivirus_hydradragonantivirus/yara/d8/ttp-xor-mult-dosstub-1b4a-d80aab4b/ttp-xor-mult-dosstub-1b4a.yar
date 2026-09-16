rule TTP_XOR_MULT_DOSStub_1b4a {
  strings:
    $key_1b4a = { 4f 22 [2] 3b 3a [2] 7c 38 [2] 3b 29 [2] 75 25 [2] 79 2f [2] 6e 24 [2] 75 6a [2] 48 }

  condition:
    any of them
}