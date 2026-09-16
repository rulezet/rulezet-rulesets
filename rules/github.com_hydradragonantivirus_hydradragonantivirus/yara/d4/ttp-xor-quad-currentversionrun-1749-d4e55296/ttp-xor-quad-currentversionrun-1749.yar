rule TTP_XOR_QUAD_CurrentVersionRun_1749 {
  strings:
    $key_1749 = { 44 26 [2] 60 28 [2] 4b 04 [2] 65 26 [2] 71 3d [2] 7e 27 [2] 60 3a [2] 62 3b [2] 79 3d [2] 65 3a [2] 79 15 }

  condition:
    any of them
}