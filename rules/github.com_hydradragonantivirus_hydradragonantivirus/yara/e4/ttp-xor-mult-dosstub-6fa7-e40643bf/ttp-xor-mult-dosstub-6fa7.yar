rule TTP_XOR_MULT_DOSStub_6fa7 {
  strings:
    $key_6fa7 = { 3b cf [2] 4f d7 [2] 08 d5 [2] 4f c4 [2] 01 c8 [2] 0d c2 [2] 1a c9 [2] 01 87 [2] 3c }

  condition:
    any of them
}