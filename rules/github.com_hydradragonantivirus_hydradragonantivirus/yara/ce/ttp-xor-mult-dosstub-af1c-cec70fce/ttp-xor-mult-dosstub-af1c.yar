rule TTP_XOR_MULT_DOSStub_af1c {
  strings:
    $key_af1c = { fb 74 [2] 8f 6c [2] c8 6e [2] 8f 7f [2] c1 73 [2] cd 79 [2] da 72 [2] c1 3c [2] fc }

  condition:
    any of them
}