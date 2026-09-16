rule TTP_XOR_MULT_DOSStub_544b {
  strings:
    $key_544b = { 00 23 [2] 74 3b [2] 33 39 [2] 74 28 [2] 3a 24 [2] 36 2e [2] 21 25 [2] 3a 6b [2] 07 }

  condition:
    any of them
}