rule TTP_XOR_MULT_DOSStub_3040 {
  strings:
    $key_3040 = { 64 28 [2] 10 30 [2] 57 32 [2] 10 23 [2] 5e 2f [2] 52 25 [2] 45 2e [2] 5e 60 [2] 63 }

  condition:
    any of them
}