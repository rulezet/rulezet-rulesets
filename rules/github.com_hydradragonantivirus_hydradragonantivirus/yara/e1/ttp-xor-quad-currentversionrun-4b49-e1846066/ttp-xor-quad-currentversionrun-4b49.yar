rule TTP_XOR_QUAD_CurrentVersionRun_4b49 {
  strings:
    $key_4b49 = { 18 26 [2] 3c 28 [2] 17 04 [2] 39 26 [2] 2d 3d [2] 22 27 [2] 3c 3a [2] 3e 3b [2] 25 3d [2] 39 3a [2] 25 15 }

  condition:
    any of them
}