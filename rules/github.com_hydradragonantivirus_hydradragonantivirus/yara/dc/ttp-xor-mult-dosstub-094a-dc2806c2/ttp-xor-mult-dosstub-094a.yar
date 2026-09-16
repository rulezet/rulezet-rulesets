rule TTP_XOR_MULT_DOSStub_094a {
  strings:
    $key_094a = { 5d 22 [2] 29 3a [2] 6e 38 [2] 29 29 [2] 67 25 [2] 6b 2f [2] 7c 24 [2] 67 6a [2] 5a }

  condition:
    any of them
}