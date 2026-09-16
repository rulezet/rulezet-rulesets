rule TTP_XOR_MULT_DOSStub_9e9d {
  strings:
    $key_9e9d = { ca f5 [2] be ed [2] f9 ef [2] be fe [2] f0 f2 [2] fc f8 [2] eb f3 [2] f0 bd [2] cd }

  condition:
    any of them
}