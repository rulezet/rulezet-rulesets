rule TTP_XOR_QUAD_CurrentVersionRun_4691 {
  strings:
    $key_4691 = { 15 fe [2] 31 f0 [2] 1a dc [2] 34 fe [2] 20 e5 [2] 2f ff [2] 31 e2 [2] 33 e3 [2] 28 e5 [2] 34 e2 [2] 28 cd }

  condition:
    any of them
}