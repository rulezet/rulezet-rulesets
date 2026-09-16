rule TTP_XOR_MULT_DOSStub_9ece {
  strings:
    $key_9ece = { ca a6 [2] be be [2] f9 bc [2] be ad [2] f0 a1 [2] fc ab [2] eb a0 [2] f0 ee [2] cd }

  condition:
    any of them
}