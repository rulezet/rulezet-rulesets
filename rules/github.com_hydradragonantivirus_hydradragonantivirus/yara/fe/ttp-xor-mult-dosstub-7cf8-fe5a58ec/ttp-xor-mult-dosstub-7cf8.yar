rule TTP_XOR_MULT_DOSStub_7cf8 {
  strings:
    $key_7cf8 = { 28 90 [2] 5c 88 [2] 1b 8a [2] 5c 9b [2] 12 97 [2] 1e 9d [2] 09 96 [2] 12 d8 [2] 2f }

  condition:
    any of them
}