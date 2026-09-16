rule TTP_XOR_QUAD_CurrentVersionRun_2149 {
  strings:
    $key_2149 = { 72 26 [2] 56 28 [2] 7d 04 [2] 53 26 [2] 47 3d [2] 48 27 [2] 56 3a [2] 54 3b [2] 4f 3d [2] 53 3a [2] 4f 15 }

  condition:
    any of them
}