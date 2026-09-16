rule TTP_XOR_MULT_DOSStub_7c1a {
  strings:
    $key_7c1a = { 28 72 [2] 5c 6a [2] 1b 68 [2] 5c 79 [2] 12 75 [2] 1e 7f [2] 09 74 [2] 12 3a [2] 2f }

  condition:
    any of them
}