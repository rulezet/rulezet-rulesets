rule TTP_XOR_MULT_DOSStub_5540 {
  strings:
    $key_5540 = { 01 28 [2] 75 30 [2] 32 32 [2] 75 23 [2] 3b 2f [2] 37 25 [2] 20 2e [2] 3b 60 [2] 06 }

  condition:
    any of them
}