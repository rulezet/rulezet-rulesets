rule TTP_XOR_MULT_DOSStub_0e57 {
  strings:
    $key_0e57 = { 5a 3f [2] 2e 27 [2] 69 25 [2] 2e 34 [2] 60 38 [2] 6c 32 [2] 7b 39 [2] 60 77 [2] 5d }

  condition:
    any of them
}