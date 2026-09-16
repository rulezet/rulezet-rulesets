rule TTP_XOR_MULT_DOSStub_af3a {
  strings:
    $key_af3a = { fb 52 [2] 8f 4a [2] c8 48 [2] 8f 59 [2] c1 55 [2] cd 5f [2] da 54 [2] c1 1a [2] fc }

  condition:
    any of them
}