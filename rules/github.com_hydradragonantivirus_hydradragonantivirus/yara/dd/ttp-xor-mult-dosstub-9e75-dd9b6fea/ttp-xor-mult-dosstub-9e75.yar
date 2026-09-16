rule TTP_XOR_MULT_DOSStub_9e75 {
  strings:
    $key_9e75 = { ca 1d [2] be 05 [2] f9 07 [2] be 16 [2] f0 1a [2] fc 10 [2] eb 1b [2] f0 55 [2] cd }

  condition:
    any of them
}