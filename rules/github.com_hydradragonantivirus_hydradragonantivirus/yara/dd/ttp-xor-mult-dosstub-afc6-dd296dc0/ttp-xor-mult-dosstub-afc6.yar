rule TTP_XOR_MULT_DOSStub_afc6 {
  strings:
    $key_afc6 = { fb ae [2] 8f b6 [2] c8 b4 [2] 8f a5 [2] c1 a9 [2] cd a3 [2] da a8 [2] c1 e6 [2] fc }

  condition:
    any of them
}