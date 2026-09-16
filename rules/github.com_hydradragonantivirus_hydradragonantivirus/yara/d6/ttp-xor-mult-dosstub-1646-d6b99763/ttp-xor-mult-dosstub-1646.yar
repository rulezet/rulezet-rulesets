rule TTP_XOR_MULT_DOSStub_1646 {
  strings:
    $key_1646 = { 42 2e [2] 36 36 [2] 71 34 [2] 36 25 [2] 78 29 [2] 74 23 [2] 63 28 [2] 78 66 [2] 45 }

  condition:
    any of them
}