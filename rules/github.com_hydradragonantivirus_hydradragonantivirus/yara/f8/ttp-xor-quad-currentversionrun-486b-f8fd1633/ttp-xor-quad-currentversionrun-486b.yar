rule TTP_XOR_QUAD_CurrentVersionRun_486b {
  strings:
    $key_486b = { 1b 04 [2] 3f 0a [2] 14 26 [2] 3a 04 [2] 2e 1f [2] 21 05 [2] 3f 18 [2] 3d 19 [2] 26 1f [2] 3a 18 [2] 26 37 }

  condition:
    any of them
}