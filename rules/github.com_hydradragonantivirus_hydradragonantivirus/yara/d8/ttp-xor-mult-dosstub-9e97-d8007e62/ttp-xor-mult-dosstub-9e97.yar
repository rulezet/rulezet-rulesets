rule TTP_XOR_MULT_DOSStub_9e97 {
  strings:
    $key_9e97 = { ca ff [2] be e7 [2] f9 e5 [2] be f4 [2] f0 f8 [2] fc f2 [2] eb f9 [2] f0 b7 [2] cd }

  condition:
    any of them
}