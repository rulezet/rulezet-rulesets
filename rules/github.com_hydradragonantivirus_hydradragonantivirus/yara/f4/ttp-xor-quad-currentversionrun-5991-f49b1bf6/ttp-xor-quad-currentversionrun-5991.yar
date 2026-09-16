rule TTP_XOR_QUAD_CurrentVersionRun_5991 {
  strings:
    $key_5991 = { 0a fe [2] 2e f0 [2] 05 dc [2] 2b fe [2] 3f e5 [2] 30 ff [2] 2e e2 [2] 2c e3 [2] 37 e5 [2] 2b e2 [2] 37 cd }

  condition:
    any of them
}