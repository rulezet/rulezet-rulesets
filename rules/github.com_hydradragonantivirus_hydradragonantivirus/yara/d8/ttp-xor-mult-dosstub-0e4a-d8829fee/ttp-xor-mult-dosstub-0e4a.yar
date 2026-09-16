rule TTP_XOR_MULT_DOSStub_0e4a {
  strings:
    $key_0e4a = { 5a 22 [2] 2e 3a [2] 69 38 [2] 2e 29 [2] 60 25 [2] 6c 2f [2] 7b 24 [2] 60 6a [2] 5d }

  condition:
    any of them
}