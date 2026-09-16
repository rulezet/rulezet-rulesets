rule TTP_XOR_MULT_DOSStub_afbc {
  strings:
    $key_afbc = { fb d4 [2] 8f cc [2] c8 ce [2] 8f df [2] c1 d3 [2] cd d9 [2] da d2 [2] c1 9c [2] fc }

  condition:
    any of them
}