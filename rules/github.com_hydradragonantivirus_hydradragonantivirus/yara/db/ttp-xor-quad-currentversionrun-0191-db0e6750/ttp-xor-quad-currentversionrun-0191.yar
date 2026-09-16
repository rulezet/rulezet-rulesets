rule TTP_XOR_QUAD_CurrentVersionRun_0191 {
  strings:
    $key_0191 = { 52 fe [2] 76 f0 [2] 5d dc [2] 73 fe [2] 67 e5 [2] 68 ff [2] 76 e2 [2] 74 e3 [2] 6f e5 [2] 73 e2 [2] 6f cd }

  condition:
    any of them
}