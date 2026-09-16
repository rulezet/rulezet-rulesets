rule TTP_XOR_MULT_DOSStub_82e7 {
  strings:
    $key_82e7 = { d6 8f [2] a2 97 [2] e5 95 [2] a2 84 [2] ec 88 [2] e0 82 [2] f7 89 [2] ec c7 [2] d1 }

  condition:
    any of them
}