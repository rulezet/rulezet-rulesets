rule TTP_XOR_MULT_DOSStub_3540 {
  strings:
    $key_3540 = { 61 28 [2] 15 30 [2] 52 32 [2] 15 23 [2] 5b 2f [2] 57 25 [2] 40 2e [2] 5b 60 [2] 66 }

  condition:
    any of them
}