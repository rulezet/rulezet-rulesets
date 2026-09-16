rule TTP_XOR_QUAD_CurrentVersionRun_7109 {
  strings:
    $key_7109 = { 22 66 [2] 06 68 [2] 2d 44 [2] 03 66 [2] 17 7d [2] 18 67 [2] 06 7a [2] 04 7b [2] 1f 7d [2] 03 7a [2] 1f 55 }

  condition:
    any of them
}