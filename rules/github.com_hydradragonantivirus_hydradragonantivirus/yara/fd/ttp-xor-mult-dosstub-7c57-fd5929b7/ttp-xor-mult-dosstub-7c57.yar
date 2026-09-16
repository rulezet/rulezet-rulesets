rule TTP_XOR_MULT_DOSStub_7c57 {
  strings:
    $key_7c57 = { 28 3f [2] 5c 27 [2] 1b 25 [2] 5c 34 [2] 12 38 [2] 1e 32 [2] 09 39 [2] 12 77 [2] 2f }

  condition:
    any of them
}