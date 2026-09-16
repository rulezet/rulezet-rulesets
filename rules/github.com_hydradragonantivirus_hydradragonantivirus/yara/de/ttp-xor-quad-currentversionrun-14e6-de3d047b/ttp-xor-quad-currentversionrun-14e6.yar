rule TTP_XOR_QUAD_CurrentVersionRun_14e6 {
  strings:
    $key_14e6 = { 47 89 [2] 63 87 [2] 48 ab [2] 66 89 [2] 72 92 [2] 7d 88 [2] 63 95 [2] 61 94 [2] 7a 92 [2] 66 95 [2] 7a ba }

  condition:
    any of them
}