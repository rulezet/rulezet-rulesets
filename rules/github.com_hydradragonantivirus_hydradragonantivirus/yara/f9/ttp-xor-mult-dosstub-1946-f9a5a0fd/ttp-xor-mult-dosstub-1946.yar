rule TTP_XOR_MULT_DOSStub_1946 {
  strings:
    $key_1946 = { 4d 2e [2] 39 36 [2] 7e 34 [2] 39 25 [2] 77 29 [2] 7b 23 [2] 6c 28 [2] 77 66 [2] 4a }

  condition:
    any of them
}