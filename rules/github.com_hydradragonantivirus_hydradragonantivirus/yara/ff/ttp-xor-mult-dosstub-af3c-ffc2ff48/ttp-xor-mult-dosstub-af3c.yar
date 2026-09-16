rule TTP_XOR_MULT_DOSStub_af3c {
  strings:
    $key_af3c = { fb 54 [2] 8f 4c [2] c8 4e [2] 8f 5f [2] c1 53 [2] cd 59 [2] da 52 [2] c1 1c [2] fc }

  condition:
    any of them
}