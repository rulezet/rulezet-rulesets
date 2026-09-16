rule TTP_XOR_QUAD_CurrentVersionRun_1591 {
  strings:
    $key_1591 = { 46 fe [2] 62 f0 [2] 49 dc [2] 67 fe [2] 73 e5 [2] 7c ff [2] 62 e2 [2] 60 e3 [2] 7b e5 [2] 67 e2 [2] 7b cd }

  condition:
    any of them
}