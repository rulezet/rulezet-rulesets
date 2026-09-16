rule TTP_XOR_QUAD_CurrentVersionRun_2891 {
  strings:
    $key_2891 = { 7b fe [2] 5f f0 [2] 74 dc [2] 5a fe [2] 4e e5 [2] 41 ff [2] 5f e2 [2] 5d e3 [2] 46 e5 [2] 5a e2 [2] 46 cd }

  condition:
    any of them
}