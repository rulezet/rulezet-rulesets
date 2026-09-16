rule TTP_XOR_QUAD_CurrentVersionRun_6791 {
  strings:
    $key_6791 = { 34 fe [2] 10 f0 [2] 3b dc [2] 15 fe [2] 01 e5 [2] 0e ff [2] 10 e2 [2] 12 e3 [2] 09 e5 [2] 15 e2 [2] 09 cd }

  condition:
    any of them
}