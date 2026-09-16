rule TTP_XOR_MULT_DOSStub_aa8f {
  strings:
    $key_aa8f = { fe e7 [2] 8a ff [2] cd fd [2] 8a ec [2] c4 e0 [2] c8 ea [2] df e1 [2] c4 af [2] f9 }

  condition:
    any of them
}