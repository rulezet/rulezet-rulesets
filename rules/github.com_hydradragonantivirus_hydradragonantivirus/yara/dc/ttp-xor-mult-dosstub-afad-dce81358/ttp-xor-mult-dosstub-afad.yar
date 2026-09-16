rule TTP_XOR_MULT_DOSStub_afad {
  strings:
    $key_afad = { fb c5 [2] 8f dd [2] c8 df [2] 8f ce [2] c1 c2 [2] cd c8 [2] da c3 [2] c1 8d [2] fc }

  condition:
    any of them
}