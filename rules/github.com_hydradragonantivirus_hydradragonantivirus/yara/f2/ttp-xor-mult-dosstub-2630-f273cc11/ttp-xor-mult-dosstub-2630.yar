rule TTP_XOR_MULT_DOSStub_2630 {
  strings:
    $key_2630 = { 72 58 [2] 06 40 [2] 41 42 [2] 06 53 [2] 48 5f [2] 44 55 [2] 53 5e [2] 48 10 [2] 75 }

  condition:
    any of them
}