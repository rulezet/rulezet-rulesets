rule TTP_XOR_MULT_DOSStub_9e91 {
  strings:
    $key_9e91 = { ca f9 [2] be e1 [2] f9 e3 [2] be f2 [2] f0 fe [2] fc f4 [2] eb ff [2] f0 b1 [2] cd }

  condition:
    any of them
}