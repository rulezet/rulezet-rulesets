rule TTP_XOR_MULT_DOSStub_1940 {
  strings:
    $key_1940 = { 4d 28 [2] 39 30 [2] 7e 32 [2] 39 23 [2] 77 2f [2] 7b 25 [2] 6c 2e [2] 77 60 [2] 4a }

  condition:
    any of them
}