rule TTP_XOR_QUAD_CurrentVersionRun_bae5 {
  strings:
    $key_bae5 = { e9 8a [2] cd 84 [2] e6 a8 [2] c8 8a [2] dc 91 [2] d3 8b [2] cd 96 [2] cf 97 [2] d4 91 [2] c8 96 [2] d4 b9 }

  condition:
    any of them
}