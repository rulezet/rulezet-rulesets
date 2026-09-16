rule TTP_XOR_QUAD_CurrentVersionRun_ba3d {
  strings:
    $key_ba3d = { e9 52 [2] cd 5c [2] e6 70 [2] c8 52 [2] dc 49 [2] d3 53 [2] cd 4e [2] cf 4f [2] d4 49 [2] c8 4e [2] d4 61 }

  condition:
    any of them
}