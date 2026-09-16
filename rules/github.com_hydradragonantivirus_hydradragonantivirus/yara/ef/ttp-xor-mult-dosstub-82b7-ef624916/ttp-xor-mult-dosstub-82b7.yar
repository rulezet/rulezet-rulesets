rule TTP_XOR_MULT_DOSStub_82b7 {
  strings:
    $key_82b7 = { d6 df [2] a2 c7 [2] e5 c5 [2] a2 d4 [2] ec d8 [2] e0 d2 [2] f7 d9 [2] ec 97 [2] d1 }

  condition:
    any of them
}