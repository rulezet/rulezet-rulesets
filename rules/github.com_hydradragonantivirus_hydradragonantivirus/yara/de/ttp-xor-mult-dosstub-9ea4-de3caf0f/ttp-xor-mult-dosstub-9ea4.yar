rule TTP_XOR_MULT_DOSStub_9ea4 {
  strings:
    $key_9ea4 = { ca cc [2] be d4 [2] f9 d6 [2] be c7 [2] f0 cb [2] fc c1 [2] eb ca [2] f0 84 [2] cd }

  condition:
    any of them
}