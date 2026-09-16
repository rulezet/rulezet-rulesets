rule TTP_XOR_MULT_DOSStub_85ce {
  strings:
    $key_85ce = { d1 a6 [2] a5 be [2] e2 bc [2] a5 ad [2] eb a1 [2] e7 ab [2] f0 a0 [2] eb ee [2] d6 }

  condition:
    any of them
}