rule TTP_XOR_MULT_DOSStub_82d4 {
  strings:
    $key_82d4 = { d6 bc [2] a2 a4 [2] e5 a6 [2] a2 b7 [2] ec bb [2] e0 b1 [2] f7 ba [2] ec f4 [2] d1 }

  condition:
    any of them
}