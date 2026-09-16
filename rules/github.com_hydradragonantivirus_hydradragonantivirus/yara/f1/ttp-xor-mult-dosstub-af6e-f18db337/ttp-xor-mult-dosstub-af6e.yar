rule TTP_XOR_MULT_DOSStub_af6e {
  strings:
    $key_af6e = { fb 06 [2] 8f 1e [2] c8 1c [2] 8f 0d [2] c1 01 [2] cd 0b [2] da 00 [2] c1 4e [2] fc }

  condition:
    any of them
}