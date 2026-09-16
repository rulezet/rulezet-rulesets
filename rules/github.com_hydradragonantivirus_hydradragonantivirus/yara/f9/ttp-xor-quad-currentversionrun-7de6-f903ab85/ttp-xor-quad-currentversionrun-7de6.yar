rule TTP_XOR_QUAD_CurrentVersionRun_7de6 {
  strings:
    $key_7de6 = { 2e 89 [2] 0a 87 [2] 21 ab [2] 0f 89 [2] 1b 92 [2] 14 88 [2] 0a 95 [2] 08 94 [2] 13 92 [2] 0f 95 [2] 13 ba }

  condition:
    any of them
}