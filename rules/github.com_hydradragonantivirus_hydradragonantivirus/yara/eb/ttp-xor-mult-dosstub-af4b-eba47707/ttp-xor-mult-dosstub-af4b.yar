rule TTP_XOR_MULT_DOSStub_af4b {
  strings:
    $key_af4b = { fb 23 [2] 8f 3b [2] c8 39 [2] 8f 28 [2] c1 24 [2] cd 2e [2] da 25 [2] c1 6b [2] fc }

  condition:
    any of them
}