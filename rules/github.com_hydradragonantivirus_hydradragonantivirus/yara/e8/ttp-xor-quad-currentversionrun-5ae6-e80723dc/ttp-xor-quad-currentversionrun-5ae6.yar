rule TTP_XOR_QUAD_CurrentVersionRun_5ae6 {
  strings:
    $key_5ae6 = { 09 89 [2] 2d 87 [2] 06 ab [2] 28 89 [2] 3c 92 [2] 33 88 [2] 2d 95 [2] 2f 94 [2] 34 92 [2] 28 95 [2] 34 ba }

  condition:
    any of them
}