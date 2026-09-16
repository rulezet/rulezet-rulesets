rule TTP_XOR_MULT_DOSStub_1ba7 {
  strings:
    $key_1ba7 = { 4f cf [2] 3b d7 [2] 7c d5 [2] 3b c4 [2] 75 c8 [2] 79 c2 [2] 6e c9 [2] 75 87 [2] 48 }

  condition:
    any of them
}