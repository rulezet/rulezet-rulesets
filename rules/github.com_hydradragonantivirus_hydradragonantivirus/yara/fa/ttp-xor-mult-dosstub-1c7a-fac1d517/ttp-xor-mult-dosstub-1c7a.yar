rule TTP_XOR_MULT_DOSStub_1c7a {
  strings:
    $key_1c7a = { 48 12 [2] 3c 0a [2] 7b 08 [2] 3c 19 [2] 72 15 [2] 7e 1f [2] 69 14 [2] 72 5a [2] 4f }

  condition:
    any of them
}