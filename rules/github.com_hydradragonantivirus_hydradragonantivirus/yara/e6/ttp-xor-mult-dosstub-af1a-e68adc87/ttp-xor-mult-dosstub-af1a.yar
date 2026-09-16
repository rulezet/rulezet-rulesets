rule TTP_XOR_MULT_DOSStub_af1a {
  strings:
    $key_af1a = { fb 72 [2] 8f 6a [2] c8 68 [2] 8f 79 [2] c1 75 [2] cd 7f [2] da 74 [2] c1 3a [2] fc }

  condition:
    any of them
}