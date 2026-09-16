rule TTP_XOR_QUAD_CurrentVersionRun_3991 {
  strings:
    $key_3991 = { 6a fe [2] 4e f0 [2] 65 dc [2] 4b fe [2] 5f e5 [2] 50 ff [2] 4e e2 [2] 4c e3 [2] 57 e5 [2] 4b e2 [2] 57 cd }

  condition:
    any of them
}