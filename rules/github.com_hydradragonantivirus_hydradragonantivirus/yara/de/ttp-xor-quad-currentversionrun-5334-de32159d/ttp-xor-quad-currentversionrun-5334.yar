rule TTP_XOR_QUAD_CurrentVersionRun_5334 {
  strings:
    $key_5334 = { 00 5b [2] 24 55 [2] 0f 79 [2] 21 5b [2] 35 40 [2] 3a 5a [2] 24 47 [2] 26 46 [2] 3d 40 [2] 21 47 [2] 3d 68 }

  condition:
    any of them
}