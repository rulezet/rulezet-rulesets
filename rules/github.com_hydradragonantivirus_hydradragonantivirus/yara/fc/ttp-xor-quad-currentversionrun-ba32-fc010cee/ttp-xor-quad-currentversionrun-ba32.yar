rule TTP_XOR_QUAD_CurrentVersionRun_ba32 {
  strings:
    $key_ba32 = { e9 5d [2] cd 53 [2] e6 7f [2] c8 5d [2] dc 46 [2] d3 5c [2] cd 41 [2] cf 40 [2] d4 46 [2] c8 41 [2] d4 6e }

  condition:
    any of them
}