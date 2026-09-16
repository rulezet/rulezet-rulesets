rule TTP_XOR_QUAD_CurrentVersionRun_ba5f {
  strings:
    $key_ba5f = { e9 30 [2] cd 3e [2] e6 12 [2] c8 30 [2] dc 2b [2] d3 31 [2] cd 2c [2] cf 2d [2] d4 2b [2] c8 2c [2] d4 03 }

  condition:
    any of them
}