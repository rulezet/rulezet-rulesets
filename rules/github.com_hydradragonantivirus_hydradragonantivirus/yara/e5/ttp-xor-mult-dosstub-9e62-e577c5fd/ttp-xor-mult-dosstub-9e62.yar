rule TTP_XOR_MULT_DOSStub_9e62 {
  strings:
    $key_9e62 = { ca 0a [2] be 12 [2] f9 10 [2] be 01 [2] f0 0d [2] fc 07 [2] eb 0c [2] f0 42 [2] cd }

  condition:
    any of them
}