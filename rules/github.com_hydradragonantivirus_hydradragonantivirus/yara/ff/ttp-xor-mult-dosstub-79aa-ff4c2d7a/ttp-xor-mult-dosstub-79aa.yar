rule TTP_XOR_MULT_DOSStub_79aa {
  strings:
    $key_79aa = { 2d c2 [2] 59 da [2] 1e d8 [2] 59 c9 [2] 17 c5 [2] 1b cf [2] 0c c4 [2] 17 8a [2] 2a }

  condition:
    any of them
}