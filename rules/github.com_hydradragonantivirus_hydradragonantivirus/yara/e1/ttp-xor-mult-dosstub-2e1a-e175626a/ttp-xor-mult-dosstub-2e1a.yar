rule TTP_XOR_MULT_DOSStub_2e1a {
  strings:
    $key_2e1a = { 7a 72 [2] 0e 6a [2] 49 68 [2] 0e 79 [2] 40 75 [2] 4c 7f [2] 5b 74 [2] 40 3a [2] 7d }

  condition:
    any of them
}