rule TTP_XOR_QUAD_CurrentVersionRun_4649 {
  strings:
    $key_4649 = { 15 26 [2] 31 28 [2] 1a 04 [2] 34 26 [2] 20 3d [2] 2f 27 [2] 31 3a [2] 33 3b [2] 28 3d [2] 34 3a [2] 28 15 }

  condition:
    any of them
}