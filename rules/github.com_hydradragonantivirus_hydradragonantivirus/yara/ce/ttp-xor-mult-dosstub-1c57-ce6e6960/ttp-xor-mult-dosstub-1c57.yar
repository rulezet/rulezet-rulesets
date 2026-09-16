rule TTP_XOR_MULT_DOSStub_1c57 {
  strings:
    $key_1c57 = { 48 3f [2] 3c 27 [2] 7b 25 [2] 3c 34 [2] 72 38 [2] 7e 32 [2] 69 39 [2] 72 77 [2] 4f }

  condition:
    any of them
}