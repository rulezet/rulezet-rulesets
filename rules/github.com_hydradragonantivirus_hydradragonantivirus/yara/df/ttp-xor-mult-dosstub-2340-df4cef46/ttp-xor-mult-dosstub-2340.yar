rule TTP_XOR_MULT_DOSStub_2340 {
  strings:
    $key_2340 = { 77 28 [2] 03 30 [2] 44 32 [2] 03 23 [2] 4d 2f [2] 41 25 [2] 56 2e [2] 4d 60 [2] 70 }

  condition:
    any of them
}