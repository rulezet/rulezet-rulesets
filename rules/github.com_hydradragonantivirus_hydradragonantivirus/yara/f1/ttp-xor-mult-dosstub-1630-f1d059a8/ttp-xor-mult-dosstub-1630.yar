rule TTP_XOR_MULT_DOSStub_1630 {
  strings:
    $key_1630 = { 42 58 [2] 36 40 [2] 71 42 [2] 36 53 [2] 78 5f [2] 74 55 [2] 63 5e [2] 78 10 [2] 45 }

  condition:
    any of them
}