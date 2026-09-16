rule TTP_XOR_MULT_DOSStub_82d7 {
  strings:
    $key_82d7 = { d6 bf [2] a2 a7 [2] e5 a5 [2] a2 b4 [2] ec b8 [2] e0 b2 [2] f7 b9 [2] ec f7 [2] d1 }

  condition:
    any of them
}