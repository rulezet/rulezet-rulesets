rule TTP_XOR_MULT_DOSStub_4c57 {
  strings:
    $key_4c57 = { 18 3f [2] 6c 27 [2] 2b 25 [2] 6c 34 [2] 22 38 [2] 2e 32 [2] 39 39 [2] 22 77 [2] 1f }

  condition:
    any of them
}