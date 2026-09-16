rule TTP_XOR_MULT_DOSStub_7db9 {
  strings:
    $key_7db9 = { 29 d1 [2] 5d c9 [2] 1a cb [2] 5d da [2] 13 d6 [2] 1f dc [2] 08 d7 [2] 13 99 [2] 2e }

  condition:
    any of them
}