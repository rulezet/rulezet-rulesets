rule TTP_XOR_MULT_DOSStub_afe8 {
  strings:
    $key_afe8 = { fb 80 [2] 8f 98 [2] c8 9a [2] 8f 8b [2] c1 87 [2] cd 8d [2] da 86 [2] c1 c8 [2] fc }

  condition:
    any of them
}