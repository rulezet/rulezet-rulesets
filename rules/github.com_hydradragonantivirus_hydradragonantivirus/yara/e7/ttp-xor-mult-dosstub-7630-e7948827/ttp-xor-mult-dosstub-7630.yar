rule TTP_XOR_MULT_DOSStub_7630 {
  strings:
    $key_7630 = { 22 58 [2] 56 40 [2] 11 42 [2] 56 53 [2] 18 5f [2] 14 55 [2] 03 5e [2] 18 10 [2] 25 }

  condition:
    any of them
}