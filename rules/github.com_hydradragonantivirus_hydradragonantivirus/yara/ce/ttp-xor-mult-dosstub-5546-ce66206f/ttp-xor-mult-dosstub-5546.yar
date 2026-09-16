rule TTP_XOR_MULT_DOSStub_5546 {
  strings:
    $key_5546 = { 01 2e [2] 75 36 [2] 32 34 [2] 75 25 [2] 3b 29 [2] 37 23 [2] 20 28 [2] 3b 66 [2] 06 }

  condition:
    any of them
}