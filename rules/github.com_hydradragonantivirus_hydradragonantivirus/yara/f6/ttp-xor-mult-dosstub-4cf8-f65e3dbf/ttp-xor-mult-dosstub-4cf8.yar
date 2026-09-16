rule TTP_XOR_MULT_DOSStub_4cf8 {
  strings:
    $key_4cf8 = { 18 90 [2] 6c 88 [2] 2b 8a [2] 6c 9b [2] 22 97 [2] 2e 9d [2] 39 96 [2] 22 d8 [2] 1f }

  condition:
    any of them
}