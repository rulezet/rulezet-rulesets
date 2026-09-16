rule TTP_XOR_QUAD_CurrentVersionRun_ba00 {
  strings:
    $key_ba00 = { e9 6f [2] cd 61 [2] e6 4d [2] c8 6f [2] dc 74 [2] d3 6e [2] cd 73 [2] cf 72 [2] d4 74 [2] c8 73 [2] d4 5c }

  condition:
    any of them
}