rule TTP_XOR_MULT_DOSStub_5040 {
  strings:
    $key_5040 = { 04 28 [2] 70 30 [2] 37 32 [2] 70 23 [2] 3e 2f [2] 32 25 [2] 25 2e [2] 3e 60 [2] 03 }

  condition:
    any of them
}