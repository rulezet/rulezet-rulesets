rule TTP_XOR_QUAD_CurrentVersionRun_1049 {
  strings:
    $key_1049 = { 43 26 [2] 67 28 [2] 4c 04 [2] 62 26 [2] 76 3d [2] 79 27 [2] 67 3a [2] 65 3b [2] 7e 3d [2] 62 3a [2] 7e 15 }

  condition:
    any of them
}