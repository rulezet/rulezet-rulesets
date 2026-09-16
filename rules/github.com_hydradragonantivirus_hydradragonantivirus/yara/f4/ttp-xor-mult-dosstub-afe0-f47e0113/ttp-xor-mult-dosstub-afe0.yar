rule TTP_XOR_MULT_DOSStub_afe0 {
  strings:
    $key_afe0 = { fb 88 [2] 8f 90 [2] c8 92 [2] 8f 83 [2] c1 8f [2] cd 85 [2] da 8e [2] c1 c0 [2] fc }

  condition:
    any of them
}