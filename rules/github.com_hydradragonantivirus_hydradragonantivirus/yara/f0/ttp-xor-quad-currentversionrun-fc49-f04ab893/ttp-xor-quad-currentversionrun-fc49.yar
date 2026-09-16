rule TTP_XOR_QUAD_CurrentVersionRun_fc49 {
  strings:
    $key_fc49 = { af 26 [2] 8b 28 [2] a0 04 [2] 8e 26 [2] 9a 3d [2] 95 27 [2] 8b 3a [2] 89 3b [2] 92 3d [2] 8e 3a [2] 92 15 }

  condition:
    any of them
}