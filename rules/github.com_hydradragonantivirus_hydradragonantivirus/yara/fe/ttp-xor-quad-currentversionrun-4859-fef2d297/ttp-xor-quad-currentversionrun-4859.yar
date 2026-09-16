rule TTP_XOR_QUAD_CurrentVersionRun_4859 {
  strings:
    $key_4859 = { 1b 36 [2] 3f 38 [2] 14 14 [2] 3a 36 [2] 2e 2d [2] 21 37 [2] 3f 2a [2] 3d 2b [2] 26 2d [2] 3a 2a [2] 26 05 }

  condition:
    any of them
}