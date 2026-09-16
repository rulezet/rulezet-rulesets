rule TTP_XOR_MULT_DOSStub_9e7c {
  strings:
    $key_9e7c = { ca 14 [2] be 0c [2] f9 0e [2] be 1f [2] f0 13 [2] fc 19 [2] eb 12 [2] f0 5c [2] cd }

  condition:
    any of them
}