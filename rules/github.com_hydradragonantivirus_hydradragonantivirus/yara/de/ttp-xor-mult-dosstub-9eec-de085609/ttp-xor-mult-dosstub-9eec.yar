rule TTP_XOR_MULT_DOSStub_9eec {
  strings:
    $key_9eec = { ca 84 [2] be 9c [2] f9 9e [2] be 8f [2] f0 83 [2] fc 89 [2] eb 82 [2] f0 cc [2] cd }

  condition:
    any of them
}