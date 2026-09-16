rule TTP_XOR_MULT_DOSStub_968b {
  strings:
    $key_968b = { c2 e3 [2] b6 fb [2] f1 f9 [2] b6 e8 [2] f8 e4 [2] f4 ee [2] e3 e5 [2] f8 ab [2] c5 }

  condition:
    any of them
}