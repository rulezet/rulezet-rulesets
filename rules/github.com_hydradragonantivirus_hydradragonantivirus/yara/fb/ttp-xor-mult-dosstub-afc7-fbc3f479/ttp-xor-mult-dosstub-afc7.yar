rule TTP_XOR_MULT_DOSStub_afc7 {
  strings:
    $key_afc7 = { fb af [2] 8f b7 [2] c8 b5 [2] 8f a4 [2] c1 a8 [2] cd a2 [2] da a9 [2] c1 e7 [2] fc }

  condition:
    any of them
}