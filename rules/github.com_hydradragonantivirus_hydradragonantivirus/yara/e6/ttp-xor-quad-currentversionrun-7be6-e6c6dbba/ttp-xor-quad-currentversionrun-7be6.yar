rule TTP_XOR_QUAD_CurrentVersionRun_7be6 {
  strings:
    $key_7be6 = { 28 89 [2] 0c 87 [2] 27 ab [2] 09 89 [2] 1d 92 [2] 12 88 [2] 0c 95 [2] 0e 94 [2] 15 92 [2] 09 95 [2] 15 ba }

  condition:
    any of them
}