rule TTP_XOR_MULT_DOSStub_1c78 {
  strings:
    $key_1c78 = { 48 10 [2] 3c 08 [2] 7b 0a [2] 3c 1b [2] 72 17 [2] 7e 1d [2] 69 16 [2] 72 58 [2] 4f }

  condition:
    any of them
}