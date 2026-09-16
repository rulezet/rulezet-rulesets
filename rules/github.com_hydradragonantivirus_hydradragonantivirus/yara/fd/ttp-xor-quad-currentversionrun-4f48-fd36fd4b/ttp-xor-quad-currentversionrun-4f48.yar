rule TTP_XOR_QUAD_CurrentVersionRun_4f48 {
  strings:
    $key_4f48 = { 1c 27 [2] 38 29 [2] 13 05 [2] 3d 27 [2] 29 3c [2] 26 26 [2] 38 3b [2] 3a 3a [2] 21 3c [2] 3d 3b [2] 21 14 }

  condition:
    any of them
}