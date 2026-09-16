rule TTP_XOR_MULT_DOSStub_82a6 {
  strings:
    $key_82a6 = { d6 ce [2] a2 d6 [2] e5 d4 [2] a2 c5 [2] ec c9 [2] e0 c3 [2] f7 c8 [2] ec 86 [2] d1 }

  condition:
    any of them
}