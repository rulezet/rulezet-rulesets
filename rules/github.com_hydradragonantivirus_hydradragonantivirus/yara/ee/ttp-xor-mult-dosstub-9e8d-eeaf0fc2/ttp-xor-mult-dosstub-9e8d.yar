rule TTP_XOR_MULT_DOSStub_9e8d {
  strings:
    $key_9e8d = { ca e5 [2] be fd [2] f9 ff [2] be ee [2] f0 e2 [2] fc e8 [2] eb e3 [2] f0 ad [2] cd }

  condition:
    any of them
}