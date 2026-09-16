rule TTP_XOR_MULT_DOSStub_9ee2 {
  strings:
    $key_9ee2 = { ca 8a [2] be 92 [2] f9 90 [2] be 81 [2] f0 8d [2] fc 87 [2] eb 8c [2] f0 c2 [2] cd }

  condition:
    any of them
}