rule TTP_XOR_MULT_DOSStub_6540 {
  strings:
    $key_6540 = { 31 28 [2] 45 30 [2] 02 32 [2] 45 23 [2] 0b 2f [2] 07 25 [2] 10 2e [2] 0b 60 [2] 36 }

  condition:
    any of them
}