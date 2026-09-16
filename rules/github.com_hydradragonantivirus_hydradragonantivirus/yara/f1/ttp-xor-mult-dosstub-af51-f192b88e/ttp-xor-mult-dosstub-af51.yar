rule TTP_XOR_MULT_DOSStub_af51 {
  strings:
    $key_af51 = { fb 39 [2] 8f 21 [2] c8 23 [2] 8f 32 [2] c1 3e [2] cd 34 [2] da 3f [2] c1 71 [2] fc }

  condition:
    any of them
}