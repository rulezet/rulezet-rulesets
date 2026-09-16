rule TTP_XOR_MULT_DOSStub_af67 {
  strings:
    $key_af67 = { fb 0f [2] 8f 17 [2] c8 15 [2] 8f 04 [2] c1 08 [2] cd 02 [2] da 09 [2] c1 47 [2] fc }

  condition:
    any of them
}