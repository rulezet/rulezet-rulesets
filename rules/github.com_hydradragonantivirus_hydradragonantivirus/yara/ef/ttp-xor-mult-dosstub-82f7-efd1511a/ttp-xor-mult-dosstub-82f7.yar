rule TTP_XOR_MULT_DOSStub_82f7 {
  strings:
    $key_82f7 = { d6 9f [2] a2 87 [2] e5 85 [2] a2 94 [2] ec 98 [2] e0 92 [2] f7 99 [2] ec d7 [2] d1 }

  condition:
    any of them
}