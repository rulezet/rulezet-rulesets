rule TTP_XOR_MULT_DOSStub_af05 {
  strings:
    $key_af05 = { fb 6d [2] 8f 75 [2] c8 77 [2] 8f 66 [2] c1 6a [2] cd 60 [2] da 6b [2] c1 25 [2] fc }

  condition:
    any of them
}