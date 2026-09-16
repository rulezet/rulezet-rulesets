rule TTP_XOR_MULT_DOSStub_4ca7 {
  strings:
    $key_4ca7 = { 18 cf [2] 6c d7 [2] 2b d5 [2] 6c c4 [2] 22 c8 [2] 2e c2 [2] 39 c9 [2] 22 87 [2] 1f }

  condition:
    any of them
}