rule TTP_XOR_MULT_DOSStub_9e80 {
  strings:
    $key_9e80 = { ca e8 [2] be f0 [2] f9 f2 [2] be e3 [2] f0 ef [2] fc e5 [2] eb ee [2] f0 a0 [2] cd }

  condition:
    any of them
}