rule TTP_XOR_QUAD_CurrentVersionRun_3e49 {
  strings:
    $key_3e49 = { 6d 26 [2] 49 28 [2] 62 04 [2] 4c 26 [2] 58 3d [2] 57 27 [2] 49 3a [2] 4b 3b [2] 50 3d [2] 4c 3a [2] 50 15 }

  condition:
    any of them
}