rule TTP_XOR_MULT_DOSStub_afd0 {
  strings:
    $key_afd0 = { fb b8 [2] 8f a0 [2] c8 a2 [2] 8f b3 [2] c1 bf [2] cd b5 [2] da be [2] c1 f0 [2] fc }

  condition:
    any of them
}