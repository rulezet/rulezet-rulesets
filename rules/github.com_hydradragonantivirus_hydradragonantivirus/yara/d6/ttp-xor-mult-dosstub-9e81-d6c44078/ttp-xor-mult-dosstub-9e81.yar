rule TTP_XOR_MULT_DOSStub_9e81 {
  strings:
    $key_9e81 = { ca e9 [2] be f1 [2] f9 f3 [2] be e2 [2] f0 ee [2] fc e4 [2] eb ef [2] f0 a1 [2] cd }

  condition:
    any of them
}