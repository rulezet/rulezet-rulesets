rule TTP_XOR_MULT_DOSStub_93ce {
  strings:
    $key_93ce = { c7 a6 [2] b3 be [2] f4 bc [2] b3 ad [2] fd a1 [2] f1 ab [2] e6 a0 [2] fd ee [2] c0 }

  condition:
    any of them
}