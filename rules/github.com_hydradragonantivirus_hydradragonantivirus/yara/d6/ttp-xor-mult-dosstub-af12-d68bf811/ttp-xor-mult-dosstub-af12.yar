rule TTP_XOR_MULT_DOSStub_af12 {
  strings:
    $key_af12 = { fb 7a [2] 8f 62 [2] c8 60 [2] 8f 71 [2] c1 7d [2] cd 77 [2] da 7c [2] c1 32 [2] fc }

  condition:
    any of them
}