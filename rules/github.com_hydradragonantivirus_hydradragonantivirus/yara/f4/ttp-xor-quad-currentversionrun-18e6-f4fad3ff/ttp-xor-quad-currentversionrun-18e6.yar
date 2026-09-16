rule TTP_XOR_QUAD_CurrentVersionRun_18e6 {
  strings:
    $key_18e6 = { 4b 89 [2] 6f 87 [2] 44 ab [2] 6a 89 [2] 7e 92 [2] 71 88 [2] 6f 95 [2] 6d 94 [2] 76 92 [2] 6a 95 [2] 76 ba }

  condition:
    any of them
}