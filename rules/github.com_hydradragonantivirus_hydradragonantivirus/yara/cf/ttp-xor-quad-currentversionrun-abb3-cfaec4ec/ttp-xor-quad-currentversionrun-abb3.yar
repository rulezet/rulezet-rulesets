rule TTP_XOR_QUAD_CurrentVersionRun_abb3 {
  strings:
    $key_abb3 = { f8 dc [2] dc d2 [2] f7 fe [2] d9 dc [2] cd c7 [2] c2 dd [2] dc c0 [2] de c1 [2] c5 c7 [2] d9 c0 [2] c5 ef }

  condition:
    any of them
}