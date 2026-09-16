rule TTP_XOR_MULT_DOSStub_af4e {
  strings:
    $key_af4e = { fb 26 [2] 8f 3e [2] c8 3c [2] 8f 2d [2] c1 21 [2] cd 2b [2] da 20 [2] c1 6e [2] fc }

  condition:
    any of them
}