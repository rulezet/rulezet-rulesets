rule TTP_XOR_QUAD_CurrentVersionRun_4f56 {
  strings:
    $key_4f56 = { 1c 39 [2] 38 37 [2] 13 1b [2] 3d 39 [2] 29 22 [2] 26 38 [2] 38 25 [2] 3a 24 [2] 21 22 [2] 3d 25 [2] 21 0a }

  condition:
    any of them
}