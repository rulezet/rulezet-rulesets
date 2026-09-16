rule TTP_XOR_QUAD_CurrentVersionRun_1891 {
  strings:
    $key_1891 = { 4b fe [2] 6f f0 [2] 44 dc [2] 6a fe [2] 7e e5 [2] 71 ff [2] 6f e2 [2] 6d e3 [2] 76 e5 [2] 6a e2 [2] 76 cd }

  condition:
    any of them
}