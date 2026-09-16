rule TTP_XOR_MULT_DOSStub_af84 {
  strings:
    $key_af84 = { fb ec [2] 8f f4 [2] c8 f6 [2] 8f e7 [2] c1 eb [2] cd e1 [2] da ea [2] c1 a4 [2] fc }

  condition:
    any of them
}