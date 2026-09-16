rule TTP_XOR_QUAD_CurrentVersionRun_2349 {
  strings:
    $key_2349 = { 70 26 [2] 54 28 [2] 7f 04 [2] 51 26 [2] 45 3d [2] 4a 27 [2] 54 3a [2] 56 3b [2] 4d 3d [2] 51 3a [2] 4d 15 }

  condition:
    any of them
}