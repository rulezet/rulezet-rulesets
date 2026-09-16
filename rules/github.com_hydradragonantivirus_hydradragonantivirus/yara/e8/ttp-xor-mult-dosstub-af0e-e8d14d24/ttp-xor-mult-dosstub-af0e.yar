rule TTP_XOR_MULT_DOSStub_af0e {
  strings:
    $key_af0e = { fb 66 [2] 8f 7e [2] c8 7c [2] 8f 6d [2] c1 61 [2] cd 6b [2] da 60 [2] c1 2e [2] fc }

  condition:
    any of them
}