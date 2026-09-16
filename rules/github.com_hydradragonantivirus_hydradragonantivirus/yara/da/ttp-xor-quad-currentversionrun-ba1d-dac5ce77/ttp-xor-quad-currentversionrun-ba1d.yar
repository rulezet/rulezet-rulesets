rule TTP_XOR_QUAD_CurrentVersionRun_ba1d {
  strings:
    $key_ba1d = { e9 72 [2] cd 7c [2] e6 50 [2] c8 72 [2] dc 69 [2] d3 73 [2] cd 6e [2] cf 6f [2] d4 69 [2] c8 6e [2] d4 41 }

  condition:
    any of them
}