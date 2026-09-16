rule TTP_XOR_QUAD_CurrentVersionRun_f549 {
  strings:
    $key_f549 = { a6 26 [2] 82 28 [2] a9 04 [2] 87 26 [2] 93 3d [2] 9c 27 [2] 82 3a [2] 80 3b [2] 9b 3d [2] 87 3a [2] 9b 15 }

  condition:
    any of them
}