rule TTP_XOR_MULT_DOSStub_7b46 {
  strings:
    $key_7b46 = { 2f 2e [2] 5b 36 [2] 1c 34 [2] 5b 25 [2] 15 29 [2] 19 23 [2] 0e 28 [2] 15 66 [2] 28 }

  condition:
    any of them
}