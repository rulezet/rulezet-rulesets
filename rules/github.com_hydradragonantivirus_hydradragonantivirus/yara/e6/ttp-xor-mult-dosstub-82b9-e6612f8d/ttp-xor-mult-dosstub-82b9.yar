rule TTP_XOR_MULT_DOSStub_82b9 {
  strings:
    $key_82b9 = { d6 d1 [2] a2 c9 [2] e5 cb [2] a2 da [2] ec d6 [2] e0 dc [2] f7 d7 [2] ec 99 [2] d1 }

  condition:
    any of them
}