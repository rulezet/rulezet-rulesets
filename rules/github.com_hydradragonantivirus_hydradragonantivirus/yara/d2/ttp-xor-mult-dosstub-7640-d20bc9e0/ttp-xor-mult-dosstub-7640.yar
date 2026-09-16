rule TTP_XOR_MULT_DOSStub_7640 {
  strings:
    $key_7640 = { 22 28 [2] 56 30 [2] 11 32 [2] 56 23 [2] 18 2f [2] 14 25 [2] 03 2e [2] 18 60 [2] 25 }

  condition:
    any of them
}