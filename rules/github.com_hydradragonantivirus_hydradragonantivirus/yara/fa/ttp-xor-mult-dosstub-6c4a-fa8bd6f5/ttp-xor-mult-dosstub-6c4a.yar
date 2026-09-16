rule TTP_XOR_MULT_DOSStub_6c4a {
  strings:
    $key_6c4a = { 38 22 [2] 4c 3a [2] 0b 38 [2] 4c 29 [2] 02 25 [2] 0e 2f [2] 19 24 [2] 02 6a [2] 3f }

  condition:
    any of them
}