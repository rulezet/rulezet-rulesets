rule TTP_XOR_MULT_DOSStub_83ce {
  strings:
    $key_83ce = { d7 a6 [2] a3 be [2] e4 bc [2] a3 ad [2] ed a1 [2] e1 ab [2] f6 a0 [2] ed ee [2] d0 }

  condition:
    any of them
}