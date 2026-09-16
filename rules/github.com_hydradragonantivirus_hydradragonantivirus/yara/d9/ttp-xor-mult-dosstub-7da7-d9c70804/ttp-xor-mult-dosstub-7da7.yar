rule TTP_XOR_MULT_DOSStub_7da7 {
  strings:
    $key_7da7 = { 29 cf [2] 5d d7 [2] 1a d5 [2] 5d c4 [2] 13 c8 [2] 1f c2 [2] 08 c9 [2] 13 87 [2] 2e }

  condition:
    any of them
}