rule TTP_XOR_MULT_DOSStub_afc4 {
  strings:
    $key_afc4 = { fb ac [2] 8f b4 [2] c8 b6 [2] 8f a7 [2] c1 ab [2] cd a1 [2] da aa [2] c1 e4 [2] fc }

  condition:
    any of them
}