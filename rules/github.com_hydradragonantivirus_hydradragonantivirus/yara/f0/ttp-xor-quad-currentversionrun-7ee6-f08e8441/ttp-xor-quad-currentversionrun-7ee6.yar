rule TTP_XOR_QUAD_CurrentVersionRun_7ee6 {
  strings:
    $key_7ee6 = { 2d 89 [2] 09 87 [2] 22 ab [2] 0c 89 [2] 18 92 [2] 17 88 [2] 09 95 [2] 0b 94 [2] 10 92 [2] 0c 95 [2] 10 ba }

  condition:
    any of them
}