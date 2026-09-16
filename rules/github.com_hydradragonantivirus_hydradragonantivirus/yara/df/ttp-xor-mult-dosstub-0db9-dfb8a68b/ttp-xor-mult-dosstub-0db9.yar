rule TTP_XOR_MULT_DOSStub_0db9 {
  strings:
    $key_0db9 = { 59 d1 [2] 2d c9 [2] 6a cb [2] 2d da [2] 63 d6 [2] 6f dc [2] 78 d7 [2] 63 99 [2] 5e }

  condition:
    any of them
}