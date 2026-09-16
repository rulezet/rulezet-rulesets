rule TTP_XOR_MULT_DOSStub_4b57 {
  strings:
    $key_4b57 = { 1f 3f [2] 6b 27 [2] 2c 25 [2] 6b 34 [2] 25 38 [2] 29 32 [2] 3e 39 [2] 25 77 [2] 18 }

  condition:
    any of them
}