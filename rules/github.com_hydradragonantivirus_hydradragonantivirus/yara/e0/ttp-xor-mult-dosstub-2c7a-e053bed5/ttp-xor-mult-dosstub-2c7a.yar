rule TTP_XOR_MULT_DOSStub_2c7a {
  strings:
    $key_2c7a = { 78 12 [2] 0c 0a [2] 4b 08 [2] 0c 19 [2] 42 15 [2] 4e 1f [2] 59 14 [2] 42 5a [2] 7f }

  condition:
    any of them
}