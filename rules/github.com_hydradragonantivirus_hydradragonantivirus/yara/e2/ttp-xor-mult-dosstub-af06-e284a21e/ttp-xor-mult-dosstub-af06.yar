rule TTP_XOR_MULT_DOSStub_af06 {
  strings:
    $key_af06 = { fb 6e [2] 8f 76 [2] c8 74 [2] 8f 65 [2] c1 69 [2] cd 63 [2] da 68 [2] c1 26 [2] fc }

  condition:
    any of them
}