rule TTP_XOR_MULT_DOSStub_1db9 {
  strings:
    $key_1db9 = { 49 d1 [2] 3d c9 [2] 7a cb [2] 3d da [2] 73 d6 [2] 7f dc [2] 68 d7 [2] 73 99 [2] 4e }

  condition:
    any of them
}