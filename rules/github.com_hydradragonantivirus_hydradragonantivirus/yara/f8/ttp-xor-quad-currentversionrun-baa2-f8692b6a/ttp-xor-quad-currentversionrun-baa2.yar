rule TTP_XOR_QUAD_CurrentVersionRun_baa2 {
  strings:
    $key_baa2 = { e9 cd [2] cd c3 [2] e6 ef [2] c8 cd [2] dc d6 [2] d3 cc [2] cd d1 [2] cf d0 [2] d4 d6 [2] c8 d1 [2] d4 fe }

  condition:
    any of them
}