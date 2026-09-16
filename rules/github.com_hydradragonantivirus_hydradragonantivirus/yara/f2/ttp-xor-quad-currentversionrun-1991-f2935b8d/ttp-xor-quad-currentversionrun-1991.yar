rule TTP_XOR_QUAD_CurrentVersionRun_1991 {
  strings:
    $key_1991 = { 4a fe [2] 6e f0 [2] 45 dc [2] 6b fe [2] 7f e5 [2] 70 ff [2] 6e e2 [2] 6c e3 [2] 77 e5 [2] 6b e2 [2] 77 cd }

  condition:
    any of them
}