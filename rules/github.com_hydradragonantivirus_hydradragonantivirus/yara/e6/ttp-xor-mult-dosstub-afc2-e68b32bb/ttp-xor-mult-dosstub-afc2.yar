rule TTP_XOR_MULT_DOSStub_afc2 {
  strings:
    $key_afc2 = { fb aa [2] 8f b2 [2] c8 b0 [2] 8f a1 [2] c1 ad [2] cd a7 [2] da ac [2] c1 e2 [2] fc }

  condition:
    any of them
}