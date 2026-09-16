rule TTP_XOR_MULT_DOSStub_4146 {
  strings:
    $key_4146 = { 15 2e [2] 61 36 [2] 26 34 [2] 61 25 [2] 2f 29 [2] 23 23 [2] 34 28 [2] 2f 66 [2] 12 }

  condition:
    any of them
}