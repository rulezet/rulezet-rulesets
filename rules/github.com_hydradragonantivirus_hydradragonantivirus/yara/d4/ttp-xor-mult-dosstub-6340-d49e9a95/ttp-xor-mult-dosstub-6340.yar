rule TTP_XOR_MULT_DOSStub_6340 {
  strings:
    $key_6340 = { 37 28 [2] 43 30 [2] 04 32 [2] 43 23 [2] 0d 2f [2] 01 25 [2] 16 2e [2] 0d 60 [2] 30 }

  condition:
    any of them
}