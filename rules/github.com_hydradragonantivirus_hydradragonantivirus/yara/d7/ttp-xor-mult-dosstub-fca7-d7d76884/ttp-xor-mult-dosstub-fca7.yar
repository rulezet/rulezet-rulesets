rule TTP_XOR_MULT_DOSStub_fca7 {
  strings:
    $key_fca7 = { a8 cf [2] dc d7 [2] 9b d5 [2] dc c4 [2] 92 c8 [2] 9e c2 [2] 89 c9 [2] 92 87 [2] af }

  condition:
    any of them
}