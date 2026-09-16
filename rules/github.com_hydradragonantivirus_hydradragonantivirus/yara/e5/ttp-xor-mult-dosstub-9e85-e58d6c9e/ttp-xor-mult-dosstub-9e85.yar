rule TTP_XOR_MULT_DOSStub_9e85 {
  strings:
    $key_9e85 = { ca ed [2] be f5 [2] f9 f7 [2] be e6 [2] f0 ea [2] fc e0 [2] eb eb [2] f0 a5 [2] cd }

  condition:
    any of them
}