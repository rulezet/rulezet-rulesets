rule TTP_XOR_QUAD_CurrentVersionRun_5ee6 {
  strings:
    $key_5ee6 = { 0d 89 [2] 29 87 [2] 02 ab [2] 2c 89 [2] 38 92 [2] 37 88 [2] 29 95 [2] 2b 94 [2] 30 92 [2] 2c 95 [2] 30 ba }

  condition:
    any of them
}