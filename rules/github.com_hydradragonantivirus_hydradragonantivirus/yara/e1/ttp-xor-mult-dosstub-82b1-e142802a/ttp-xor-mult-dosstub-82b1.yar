rule TTP_XOR_MULT_DOSStub_82b1 {
  strings:
    $key_82b1 = { d6 d9 [2] a2 c1 [2] e5 c3 [2] a2 d2 [2] ec de [2] e0 d4 [2] f7 df [2] ec 91 [2] d1 }

  condition:
    any of them
}