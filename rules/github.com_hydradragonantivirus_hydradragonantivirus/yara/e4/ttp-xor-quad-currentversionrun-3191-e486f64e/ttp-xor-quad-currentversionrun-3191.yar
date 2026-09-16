rule TTP_XOR_QUAD_CurrentVersionRun_3191 {
  strings:
    $key_3191 = { 62 fe [2] 46 f0 [2] 6d dc [2] 43 fe [2] 57 e5 [2] 58 ff [2] 46 e2 [2] 44 e3 [2] 5f e5 [2] 43 e2 [2] 5f cd }

  condition:
    any of them
}