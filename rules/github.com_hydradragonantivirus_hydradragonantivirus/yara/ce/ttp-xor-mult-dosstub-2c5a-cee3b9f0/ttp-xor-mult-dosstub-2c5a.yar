rule TTP_XOR_MULT_DOSStub_2c5a {
  strings:
    $key_2c5a = { 78 32 [2] 0c 2a [2] 4b 28 [2] 0c 39 [2] 42 35 [2] 4e 3f [2] 59 34 [2] 42 7a [2] 7f }

  condition:
    any of them
}