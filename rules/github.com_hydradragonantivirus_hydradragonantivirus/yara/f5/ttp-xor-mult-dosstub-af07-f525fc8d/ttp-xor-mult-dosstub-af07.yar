rule TTP_XOR_MULT_DOSStub_af07 {
  strings:
    $key_af07 = { fb 6f [2] 8f 77 [2] c8 75 [2] 8f 64 [2] c1 68 [2] cd 62 [2] da 69 [2] c1 27 [2] fc }

  condition:
    any of them
}