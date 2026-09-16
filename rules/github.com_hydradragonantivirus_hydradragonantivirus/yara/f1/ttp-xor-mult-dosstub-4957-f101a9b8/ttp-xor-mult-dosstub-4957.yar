rule TTP_XOR_MULT_DOSStub_4957 {
  strings:
    $key_4957 = { 1d 3f [2] 69 27 [2] 2e 25 [2] 69 34 [2] 27 38 [2] 2b 32 [2] 3c 39 [2] 27 77 [2] 1a }

  condition:
    any of them
}