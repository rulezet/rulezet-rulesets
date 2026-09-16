rule TTP_XOR_QUAD_CurrentVersionRun_ba3a {
  strings:
    $key_ba3a = { e9 55 [2] cd 5b [2] e6 77 [2] c8 55 [2] dc 4e [2] d3 54 [2] cd 49 [2] cf 48 [2] d4 4e [2] c8 49 [2] d4 66 }

  condition:
    any of them
}