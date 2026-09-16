rule TTP_XOR_MULT_DOSStub_9eee {
  strings:
    $key_9eee = { ca 86 [2] be 9e [2] f9 9c [2] be 8d [2] f0 81 [2] fc 8b [2] eb 80 [2] f0 ce [2] cd }

  condition:
    any of them
}