rule TTP_XOR_QUAD_CurrentVersionRun_7fe6 {
  strings:
    $key_7fe6 = { 2c 89 [2] 08 87 [2] 23 ab [2] 0d 89 [2] 19 92 [2] 16 88 [2] 08 95 [2] 0a 94 [2] 11 92 [2] 0d 95 [2] 11 ba }

  condition:
    any of them
}