rule TTP_XOR_MULT_DOSStub_0540 {
  strings:
    $key_0540 = { 51 28 [2] 25 30 [2] 62 32 [2] 25 23 [2] 6b 2f [2] 67 25 [2] 70 2e [2] 6b 60 [2] 56 }

  condition:
    any of them
}