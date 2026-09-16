rule TTP_XOR_MULT_DOSStub_1b46 {
  strings:
    $key_1b46 = { 4f 2e [2] 3b 36 [2] 7c 34 [2] 3b 25 [2] 75 29 [2] 79 23 [2] 6e 28 [2] 75 66 [2] 48 }

  condition:
    any of them
}