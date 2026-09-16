rule TTP_XOR_MULT_DOSStub_f1a7 {
  strings:
    $key_f1a7 = { a5 cf [2] d1 d7 [2] 96 d5 [2] d1 c4 [2] 9f c8 [2] 93 c2 [2] 84 c9 [2] 9f 87 [2] a2 }

  condition:
    any of them
}