rule TTP_XOR_QUAD_CurrentVersionRun_ba5a {
  strings:
    $key_ba5a = { e9 35 [2] cd 3b [2] e6 17 [2] c8 35 [2] dc 2e [2] d3 34 [2] cd 29 [2] cf 28 [2] d4 2e [2] c8 29 [2] d4 06 }

  condition:
    any of them
}