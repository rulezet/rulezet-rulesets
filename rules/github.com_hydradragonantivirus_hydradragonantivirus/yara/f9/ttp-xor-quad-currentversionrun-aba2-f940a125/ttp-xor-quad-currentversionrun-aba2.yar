rule TTP_XOR_QUAD_CurrentVersionRun_aba2 {
  strings:
    $key_aba2 = { f8 cd [2] dc c3 [2] f7 ef [2] d9 cd [2] cd d6 [2] c2 cc [2] dc d1 [2] de d0 [2] c5 d6 [2] d9 d1 [2] c5 fe }

  condition:
    any of them
}