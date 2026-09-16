rule TTP_XOR_MULT_DOSStub_7b57 {
  strings:
    $key_7b57 = { 2f 3f [2] 5b 27 [2] 1c 25 [2] 5b 34 [2] 15 38 [2] 19 32 [2] 0e 39 [2] 15 77 [2] 28 }

  condition:
    any of them
}