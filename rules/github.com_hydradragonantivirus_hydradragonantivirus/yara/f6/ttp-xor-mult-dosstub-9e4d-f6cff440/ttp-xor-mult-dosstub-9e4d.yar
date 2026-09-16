rule TTP_XOR_MULT_DOSStub_9e4d {
  strings:
    $key_9e4d = { ca 25 [2] be 3d [2] f9 3f [2] be 2e [2] f0 22 [2] fc 28 [2] eb 23 [2] f0 6d [2] cd }

  condition:
    any of them
}