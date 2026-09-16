rule TTP_XOR_MULT_DOSStub_9e1d {
  strings:
    $key_9e1d = { ca 75 [2] be 6d [2] f9 6f [2] be 7e [2] f0 72 [2] fc 78 [2] eb 73 [2] f0 3d [2] cd }

  condition:
    any of them
}