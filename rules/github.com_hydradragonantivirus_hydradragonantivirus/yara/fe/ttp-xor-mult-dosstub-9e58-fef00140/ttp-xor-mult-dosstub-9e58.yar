rule TTP_XOR_MULT_DOSStub_9e58 {
  strings:
    $key_9e58 = { ca 30 [2] be 28 [2] f9 2a [2] be 3b [2] f0 37 [2] fc 3d [2] eb 36 [2] f0 78 [2] cd }

  condition:
    any of them
}