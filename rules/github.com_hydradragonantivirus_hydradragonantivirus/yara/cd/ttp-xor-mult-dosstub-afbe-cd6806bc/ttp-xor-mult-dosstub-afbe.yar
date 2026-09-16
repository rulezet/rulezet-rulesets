rule TTP_XOR_MULT_DOSStub_afbe {
  strings:
    $key_afbe = { fb d6 [2] 8f ce [2] c8 cc [2] 8f dd [2] c1 d1 [2] cd db [2] da d0 [2] c1 9e [2] fc }

  condition:
    any of them
}