rule TTP_XOR_MULT_DOSStub_82ce {
  strings:
    $key_82ce = { d6 a6 [2] a2 be [2] e5 bc [2] a2 ad [2] ec a1 [2] e0 ab [2] f7 a0 [2] ec ee [2] d1 }

  condition:
    any of them
}