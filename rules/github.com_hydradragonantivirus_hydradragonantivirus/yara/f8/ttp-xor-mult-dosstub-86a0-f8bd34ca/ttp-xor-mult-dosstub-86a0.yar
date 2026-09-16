rule TTP_XOR_MULT_DOSStub_86a0 {
  strings:
    $key_86a0 = { d2 c8 [2] a6 d0 [2] e1 d2 [2] a6 c3 [2] e8 cf [2] e4 c5 [2] f3 ce [2] e8 80 [2] d5 }

  condition:
    any of them
}