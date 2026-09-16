rule TTP_XOR_MULT_DOSStub_9ea1 {
  strings:
    $key_9ea1 = { ca c9 [2] be d1 [2] f9 d3 [2] be c2 [2] f0 ce [2] fc c4 [2] eb cf [2] f0 81 [2] cd }

  condition:
    any of them
}