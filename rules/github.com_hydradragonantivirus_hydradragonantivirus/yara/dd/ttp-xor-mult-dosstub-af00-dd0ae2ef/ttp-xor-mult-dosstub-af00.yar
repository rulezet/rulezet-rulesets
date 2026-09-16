rule TTP_XOR_MULT_DOSStub_af00 {
  strings:
    $key_af00 = { fb 68 [2] 8f 70 [2] c8 72 [2] 8f 63 [2] c1 6f [2] cd 65 [2] da 6e [2] c1 20 [2] fc }

  condition:
    any of them
}