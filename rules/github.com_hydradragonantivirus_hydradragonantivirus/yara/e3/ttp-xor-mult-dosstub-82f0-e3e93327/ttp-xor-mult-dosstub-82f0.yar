rule TTP_XOR_MULT_DOSStub_82f0 {
  strings:
    $key_82f0 = { d6 98 [2] a2 80 [2] e5 82 [2] a2 93 [2] ec 9f [2] e0 95 [2] f7 9e [2] ec d0 [2] d1 }

  condition:
    any of them
}