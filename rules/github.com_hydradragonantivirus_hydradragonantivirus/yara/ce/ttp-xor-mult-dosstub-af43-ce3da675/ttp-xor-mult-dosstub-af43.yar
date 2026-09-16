rule TTP_XOR_MULT_DOSStub_af43 {
  strings:
    $key_af43 = { fb 2b [2] 8f 33 [2] c8 31 [2] 8f 20 [2] c1 2c [2] cd 26 [2] da 2d [2] c1 63 [2] fc }

  condition:
    any of them
}