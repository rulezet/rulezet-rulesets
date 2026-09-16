rule TTP_XOR_MULT_DOSStub_4b1a {
  strings:
    $key_4b1a = { 1f 72 [2] 6b 6a [2] 2c 68 [2] 6b 79 [2] 25 75 [2] 29 7f [2] 3e 74 [2] 25 3a [2] 18 }

  condition:
    any of them
}