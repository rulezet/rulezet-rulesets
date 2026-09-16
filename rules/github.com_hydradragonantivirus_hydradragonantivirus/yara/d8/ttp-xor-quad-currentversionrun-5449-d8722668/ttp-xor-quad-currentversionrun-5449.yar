rule TTP_XOR_QUAD_CurrentVersionRun_5449 {
  strings:
    $key_5449 = { 07 26 [2] 23 28 [2] 08 04 [2] 26 26 [2] 32 3d [2] 3d 27 [2] 23 3a [2] 21 3b [2] 3a 3d [2] 26 3a [2] 3a 15 }

  condition:
    any of them
}