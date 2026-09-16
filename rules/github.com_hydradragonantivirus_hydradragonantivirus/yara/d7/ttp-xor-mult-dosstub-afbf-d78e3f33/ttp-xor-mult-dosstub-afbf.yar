rule TTP_XOR_MULT_DOSStub_afbf {
  strings:
    $key_afbf = { fb d7 [2] 8f cf [2] c8 cd [2] 8f dc [2] c1 d0 [2] cd da [2] da d1 [2] c1 9f [2] fc }

  condition:
    any of them
}