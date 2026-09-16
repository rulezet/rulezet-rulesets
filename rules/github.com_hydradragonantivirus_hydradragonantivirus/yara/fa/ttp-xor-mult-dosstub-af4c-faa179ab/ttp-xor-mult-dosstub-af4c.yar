rule TTP_XOR_MULT_DOSStub_af4c {
  strings:
    $key_af4c = { fb 24 [2] 8f 3c [2] c8 3e [2] 8f 2f [2] c1 23 [2] cd 29 [2] da 22 [2] c1 6c [2] fc }

  condition:
    any of them
}