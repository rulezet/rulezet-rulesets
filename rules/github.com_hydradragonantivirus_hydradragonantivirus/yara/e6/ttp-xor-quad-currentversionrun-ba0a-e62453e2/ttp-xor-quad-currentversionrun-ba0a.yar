rule TTP_XOR_QUAD_CurrentVersionRun_ba0a {
  strings:
    $key_ba0a = { e9 65 [2] cd 6b [2] e6 47 [2] c8 65 [2] dc 7e [2] d3 64 [2] cd 79 [2] cf 78 [2] d4 7e [2] c8 79 [2] d4 56 }

  condition:
    any of them
}