rule TTP_XOR_MULT_DOSStub_654a {
  strings:
    $key_654a = { 31 22 [2] 45 3a [2] 02 38 [2] 45 29 [2] 0b 25 [2] 07 2f [2] 10 24 [2] 0b 6a [2] 36 }

  condition:
    any of them
}