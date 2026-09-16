rule TTP_XOR_MULT_DOSStub_affe {
  strings:
    $key_affe = { fb 96 [2] 8f 8e [2] c8 8c [2] 8f 9d [2] c1 91 [2] cd 9b [2] da 90 [2] c1 de [2] fc }

  condition:
    any of them
}