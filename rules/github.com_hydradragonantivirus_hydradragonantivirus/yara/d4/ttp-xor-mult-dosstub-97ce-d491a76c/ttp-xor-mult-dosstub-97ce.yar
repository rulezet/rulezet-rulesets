rule TTP_XOR_MULT_DOSStub_97ce {
  strings:
    $key_97ce = { c3 a6 [2] b7 be [2] f0 bc [2] b7 ad [2] f9 a1 [2] f5 ab [2] e2 a0 [2] f9 ee [2] c4 }

  condition:
    any of them
}