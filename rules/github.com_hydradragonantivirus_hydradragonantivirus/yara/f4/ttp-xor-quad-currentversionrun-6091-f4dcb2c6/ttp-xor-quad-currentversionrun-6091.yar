rule TTP_XOR_QUAD_CurrentVersionRun_6091 {
  strings:
    $key_6091 = { 33 fe [2] 17 f0 [2] 3c dc [2] 12 fe [2] 06 e5 [2] 09 ff [2] 17 e2 [2] 15 e3 [2] 0e e5 [2] 12 e2 [2] 0e cd }

  condition:
    any of them
}