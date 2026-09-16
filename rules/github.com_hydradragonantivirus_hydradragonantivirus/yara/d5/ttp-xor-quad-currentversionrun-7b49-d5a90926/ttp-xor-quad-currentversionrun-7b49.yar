rule TTP_XOR_QUAD_CurrentVersionRun_7b49 {
  strings:
    $key_7b49 = { 28 26 [2] 0c 28 [2] 27 04 [2] 09 26 [2] 1d 3d [2] 12 27 [2] 0c 3a [2] 0e 3b [2] 15 3d [2] 09 3a [2] 15 15 }

  condition:
    any of them
}