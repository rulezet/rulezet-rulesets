rule TTP_XOR_MULT_DOSStub_9eac {
  strings:
    $key_9eac = { ca c4 [2] be dc [2] f9 de [2] be cf [2] f0 c3 [2] fc c9 [2] eb c2 [2] f0 8c [2] cd }

  condition:
    any of them
}