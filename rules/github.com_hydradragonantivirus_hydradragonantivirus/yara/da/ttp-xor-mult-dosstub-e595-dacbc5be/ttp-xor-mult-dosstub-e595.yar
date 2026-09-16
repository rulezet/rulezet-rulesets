rule TTP_XOR_MULT_DOSStub_e595 {
  strings:
    $key_e595 = { b1 fd [2] c5 e5 [2] 82 e7 [2] c5 f6 [2] 8b fa [2] 87 f0 [2] 90 fb [2] 8b b5 [2] b6 }

  condition:
    any of them
}