rule TTP_XOR_MULT_DOSStub_1641 {
  strings:
    $key_1641 = { 42 29 [2] 36 31 [2] 71 33 [2] 36 22 [2] 78 2e [2] 74 24 [2] 63 2f [2] 78 61 [2] 45 }

  condition:
    any of them
}