rule TTP_XOR_MULT_DOSStub_82c3 {
  strings:
    $key_82c3 = { d6 ab [2] a2 b3 [2] e5 b1 [2] a2 a0 [2] ec ac [2] e0 a6 [2] f7 ad [2] ec e3 [2] d1 }

  condition:
    any of them
}