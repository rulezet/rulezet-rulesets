rule TTP_XOR_MULT_DOSStub_af0d {
  strings:
    $key_af0d = { fb 65 [2] 8f 7d [2] c8 7f [2] 8f 6e [2] c1 62 [2] cd 68 [2] da 63 [2] c1 2d [2] fc }

  condition:
    any of them
}