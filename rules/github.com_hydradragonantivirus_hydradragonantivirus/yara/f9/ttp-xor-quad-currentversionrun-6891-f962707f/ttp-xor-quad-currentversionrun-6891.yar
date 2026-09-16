rule TTP_XOR_QUAD_CurrentVersionRun_6891 {
  strings:
    $key_6891 = { 3b fe [2] 1f f0 [2] 34 dc [2] 1a fe [2] 0e e5 [2] 01 ff [2] 1f e2 [2] 1d e3 [2] 06 e5 [2] 1a e2 [2] 06 cd }

  condition:
    any of them
}