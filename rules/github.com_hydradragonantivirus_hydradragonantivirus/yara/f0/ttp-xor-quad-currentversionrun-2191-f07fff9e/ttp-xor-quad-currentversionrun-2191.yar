rule TTP_XOR_QUAD_CurrentVersionRun_2191 {
  strings:
    $key_2191 = { 72 fe [2] 56 f0 [2] 7d dc [2] 53 fe [2] 47 e5 [2] 48 ff [2] 56 e2 [2] 54 e3 [2] 4f e5 [2] 53 e2 [2] 4f cd }

  condition:
    any of them
}