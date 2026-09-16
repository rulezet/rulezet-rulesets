rule TTP_XOR_MULT_DOSStub_82a7 {
  strings:
    $key_82a7 = { d6 cf [2] a2 d7 [2] e5 d5 [2] a2 c4 [2] ec c8 [2] e0 c2 [2] f7 c9 [2] ec 87 [2] d1 }

  condition:
    any of them
}