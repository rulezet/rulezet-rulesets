rule TTP_XOR_MULT_DOSStub_9e10 {
  strings:
    $key_9e10 = { ca 78 [2] be 60 [2] f9 62 [2] be 73 [2] f0 7f [2] fc 75 [2] eb 7e [2] f0 30 [2] cd }

  condition:
    any of them
}