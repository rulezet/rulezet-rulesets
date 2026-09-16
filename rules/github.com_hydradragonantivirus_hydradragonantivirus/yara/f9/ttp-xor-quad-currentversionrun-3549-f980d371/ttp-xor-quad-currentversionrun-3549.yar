rule TTP_XOR_QUAD_CurrentVersionRun_3549 {
  strings:
    $key_3549 = { 66 26 [2] 42 28 [2] 69 04 [2] 47 26 [2] 53 3d [2] 5c 27 [2] 42 3a [2] 40 3b [2] 5b 3d [2] 47 3a [2] 5b 15 }

  condition:
    any of them
}