rule TTP_XOR_MULT_DOSStub_1ce7 {
  strings:
    $key_1ce7 = { 48 8f [2] 3c 97 [2] 7b 95 [2] 3c 84 [2] 72 88 [2] 7e 82 [2] 69 89 [2] 72 c7 [2] 4f }

  condition:
    any of them
}