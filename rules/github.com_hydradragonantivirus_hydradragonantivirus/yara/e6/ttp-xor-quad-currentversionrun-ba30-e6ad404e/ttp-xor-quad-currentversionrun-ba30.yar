rule TTP_XOR_QUAD_CurrentVersionRun_ba30 {
  strings:
    $key_ba30 = { e9 5f [2] cd 51 [2] e6 7d [2] c8 5f [2] dc 44 [2] d3 5e [2] cd 43 [2] cf 42 [2] d4 44 [2] c8 43 [2] d4 6c }

  condition:
    any of them
}