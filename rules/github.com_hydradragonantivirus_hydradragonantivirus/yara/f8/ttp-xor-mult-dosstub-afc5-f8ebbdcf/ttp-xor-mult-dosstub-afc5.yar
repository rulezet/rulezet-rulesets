rule TTP_XOR_MULT_DOSStub_afc5 {
  strings:
    $key_afc5 = { fb ad [2] 8f b5 [2] c8 b7 [2] 8f a6 [2] c1 aa [2] cd a0 [2] da ab [2] c1 e5 [2] fc }

  condition:
    any of them
}