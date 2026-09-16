rule TTP_XOR_MULT_DOSStub_9e6c {
  strings:
    $key_9e6c = { ca 04 [2] be 1c [2] f9 1e [2] be 0f [2] f0 03 [2] fc 09 [2] eb 02 [2] f0 4c [2] cd }

  condition:
    any of them
}