rule TTP_XOR_QUAD_CurrentVersionRun_1849 {
  strings:
    $key_1849 = { 4b 26 [2] 6f 28 [2] 44 04 [2] 6a 26 [2] 7e 3d [2] 71 27 [2] 6f 3a [2] 6d 3b [2] 76 3d [2] 6a 3a [2] 76 15 }

  condition:
    any of them
}