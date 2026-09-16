rule TTP_XOR_QUAD_CurrentVersionRun_f649 {
  strings:
    $key_f649 = { a5 26 [2] 81 28 [2] aa 04 [2] 84 26 [2] 90 3d [2] 9f 27 [2] 81 3a [2] 83 3b [2] 98 3d [2] 84 3a [2] 98 15 }

  condition:
    any of them
}