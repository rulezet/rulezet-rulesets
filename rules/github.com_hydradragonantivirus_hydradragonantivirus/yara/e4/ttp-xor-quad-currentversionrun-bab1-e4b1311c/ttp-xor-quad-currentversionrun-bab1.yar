rule TTP_XOR_QUAD_CurrentVersionRun_bab1 {
  strings:
    $key_bab1 = { e9 de [2] cd d0 [2] e6 fc [2] c8 de [2] dc c5 [2] d3 df [2] cd c2 [2] cf c3 [2] d4 c5 [2] c8 c2 [2] d4 ed }

  condition:
    any of them
}