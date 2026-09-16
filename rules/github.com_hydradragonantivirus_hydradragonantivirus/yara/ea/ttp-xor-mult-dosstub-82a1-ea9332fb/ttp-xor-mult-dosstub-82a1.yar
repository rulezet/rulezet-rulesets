rule TTP_XOR_MULT_DOSStub_82a1 {
  strings:
    $key_82a1 = { d6 c9 [2] a2 d1 [2] e5 d3 [2] a2 c2 [2] ec ce [2] e0 c4 [2] f7 cf [2] ec 81 [2] d1 }

  condition:
    any of them
}