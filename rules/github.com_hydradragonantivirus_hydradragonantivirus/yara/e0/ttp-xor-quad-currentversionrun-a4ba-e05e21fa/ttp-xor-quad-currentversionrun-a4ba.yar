rule TTP_XOR_QUAD_CurrentVersionRun_a4ba {
  strings:
    $key_a4ba = { f7 d5 [2] d3 db [2] f8 f7 [2] d6 d5 [2] c2 ce [2] cd d4 [2] d3 c9 [2] d1 c8 [2] ca ce [2] d6 c9 [2] ca e6 }

  condition:
    any of them
}