rule TTP_XOR_MULT_DOSStub_0f46 {
  strings:
    $key_0f46 = { 5b 2e [2] 2f 36 [2] 68 34 [2] 2f 25 [2] 61 29 [2] 6d 23 [2] 7a 28 [2] 61 66 [2] 5c }

  condition:
    any of them
}