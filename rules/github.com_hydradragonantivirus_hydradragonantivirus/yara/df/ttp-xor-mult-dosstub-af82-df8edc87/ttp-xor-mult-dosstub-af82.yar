rule TTP_XOR_MULT_DOSStub_af82 {
  strings:
    $key_af82 = { fb ea [2] 8f f2 [2] c8 f0 [2] 8f e1 [2] c1 ed [2] cd e7 [2] da ec [2] c1 a2 [2] fc }

  condition:
    any of them
}