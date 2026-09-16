rule TTP_XOR_MULT_DOSStub_af31 {
  strings:
    $key_af31 = { fb 59 [2] 8f 41 [2] c8 43 [2] 8f 52 [2] c1 5e [2] cd 54 [2] da 5f [2] c1 11 [2] fc }

  condition:
    any of them
}