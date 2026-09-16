rule TTP_XOR_QUAD_CurrentVersionRun_2991 {
  strings:
    $key_2991 = { 7a fe [2] 5e f0 [2] 75 dc [2] 5b fe [2] 4f e5 [2] 40 ff [2] 5e e2 [2] 5c e3 [2] 47 e5 [2] 5b e2 [2] 47 cd }

  condition:
    any of them
}