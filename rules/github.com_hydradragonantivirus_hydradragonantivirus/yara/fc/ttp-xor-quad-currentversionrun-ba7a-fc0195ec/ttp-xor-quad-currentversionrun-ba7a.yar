rule TTP_XOR_QUAD_CurrentVersionRun_ba7a {
  strings:
    $key_ba7a = { e9 15 [2] cd 1b [2] e6 37 [2] c8 15 [2] dc 0e [2] d3 14 [2] cd 09 [2] cf 08 [2] d4 0e [2] c8 09 [2] d4 26 }

  condition:
    any of them
}