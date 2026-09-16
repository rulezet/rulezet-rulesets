rule TTP_XOR_MULT_DOSStub_9eb4 {
  strings:
    $key_9eb4 = { ca dc [2] be c4 [2] f9 c6 [2] be d7 [2] f0 db [2] fc d1 [2] eb da [2] f0 94 [2] cd }

  condition:
    any of them
}