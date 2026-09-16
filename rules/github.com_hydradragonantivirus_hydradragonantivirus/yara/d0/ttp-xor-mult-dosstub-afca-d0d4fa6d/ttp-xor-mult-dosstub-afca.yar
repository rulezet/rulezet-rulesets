rule TTP_XOR_MULT_DOSStub_afca {
  strings:
    $key_afca = { fb a2 [2] 8f ba [2] c8 b8 [2] 8f a9 [2] c1 a5 [2] cd af [2] da a4 [2] c1 ea [2] fc }

  condition:
    any of them
}