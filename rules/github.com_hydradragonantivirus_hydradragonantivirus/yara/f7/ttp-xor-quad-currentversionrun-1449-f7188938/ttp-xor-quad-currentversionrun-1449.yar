rule TTP_XOR_QUAD_CurrentVersionRun_1449 {
  strings:
    $key_1449 = { 47 26 [2] 63 28 [2] 48 04 [2] 66 26 [2] 72 3d [2] 7d 27 [2] 63 3a [2] 61 3b [2] 7a 3d [2] 66 3a [2] 7a 15 }

  condition:
    any of them
}