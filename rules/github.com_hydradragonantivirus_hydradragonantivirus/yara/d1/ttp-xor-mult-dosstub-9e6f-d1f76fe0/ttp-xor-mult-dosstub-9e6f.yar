rule TTP_XOR_MULT_DOSStub_9e6f {
  strings:
    $key_9e6f = { ca 07 [2] be 1f [2] f9 1d [2] be 0c [2] f0 00 [2] fc 0a [2] eb 01 [2] f0 4f [2] cd }

  condition:
    any of them
}