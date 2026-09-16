rule TTP_XOR_MULT_DOSStub_aff4 {
  strings:
    $key_aff4 = { fb 9c [2] 8f 84 [2] c8 86 [2] 8f 97 [2] c1 9b [2] cd 91 [2] da 9a [2] c1 d4 [2] fc }

  condition:
    any of them
}