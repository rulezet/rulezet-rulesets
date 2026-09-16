rule TTP_XOR_MULT_DOSStub_9e84 {
  strings:
    $key_9e84 = { ca ec [2] be f4 [2] f9 f6 [2] be e7 [2] f0 eb [2] fc e1 [2] eb ea [2] f0 a4 [2] cd }

  condition:
    any of them
}