rule TTP_XOR_MULT_DOSStub_9e3c {
  strings:
    $key_9e3c = { ca 54 [2] be 4c [2] f9 4e [2] be 5f [2] f0 53 [2] fc 59 [2] eb 52 [2] f0 1c [2] cd }

  condition:
    any of them
}