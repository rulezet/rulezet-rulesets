rule TTP_XOR_QUAD_CurrentVersionRun_4f09 {
  strings:
    $key_4f09 = { 1c 66 [2] 38 68 [2] 13 44 [2] 3d 66 [2] 29 7d [2] 26 67 [2] 38 7a [2] 3a 7b [2] 21 7d [2] 3d 7a [2] 21 55 }

  condition:
    any of them
}