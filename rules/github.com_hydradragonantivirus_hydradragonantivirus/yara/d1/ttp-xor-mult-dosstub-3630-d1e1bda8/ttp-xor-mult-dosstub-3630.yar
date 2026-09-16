rule TTP_XOR_MULT_DOSStub_3630 {
  strings:
    $key_3630 = { 62 58 [2] 16 40 [2] 51 42 [2] 16 53 [2] 58 5f [2] 54 55 [2] 43 5e [2] 58 10 [2] 65 }

  condition:
    any of them
}