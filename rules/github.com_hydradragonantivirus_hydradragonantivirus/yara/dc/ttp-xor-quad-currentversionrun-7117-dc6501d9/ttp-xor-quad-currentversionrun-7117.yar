rule TTP_XOR_QUAD_CurrentVersionRun_7117 {
  strings:
    $key_7117 = { 22 78 [2] 06 76 [2] 2d 5a [2] 03 78 [2] 17 63 [2] 18 79 [2] 06 64 [2] 04 65 [2] 1f 63 [2] 03 64 [2] 1f 4b }

  condition:
    any of them
}