rule TTP_XOR_QUAD_CurrentVersionRun_4191 {
  strings:
    $key_4191 = { 12 fe [2] 36 f0 [2] 1d dc [2] 33 fe [2] 27 e5 [2] 28 ff [2] 36 e2 [2] 34 e3 [2] 2f e5 [2] 33 e2 [2] 2f cd }

  condition:
    any of them
}