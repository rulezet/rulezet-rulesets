rule TTP_XOR_QUAD_CurrentVersionRun_b5ba {
  strings:
    $key_b5ba = { e6 d5 [2] c2 db [2] e9 f7 [2] c7 d5 [2] d3 ce [2] dc d4 [2] c2 c9 [2] c0 c8 [2] db ce [2] c7 c9 [2] db e6 }

  condition:
    any of them
}