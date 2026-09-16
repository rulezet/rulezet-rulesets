rule TTP_XOR_QUAD_CurrentVersionRun_ba3f {
  strings:
    $key_ba3f = { e9 50 [2] cd 5e [2] e6 72 [2] c8 50 [2] dc 4b [2] d3 51 [2] cd 4c [2] cf 4d [2] d4 4b [2] c8 4c [2] d4 63 }

  condition:
    any of them
}