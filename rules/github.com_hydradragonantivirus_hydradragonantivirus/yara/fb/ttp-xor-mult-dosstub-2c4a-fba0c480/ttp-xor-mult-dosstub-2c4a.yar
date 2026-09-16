rule TTP_XOR_MULT_DOSStub_2c4a {
  strings:
    $key_2c4a = { 78 22 [2] 0c 3a [2] 4b 38 [2] 0c 29 [2] 42 25 [2] 4e 2f [2] 59 24 [2] 42 6a [2] 7f }

  condition:
    any of them
}