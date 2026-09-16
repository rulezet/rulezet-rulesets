rule TTP_XOR_QUAD_CurrentVersionRun_5891 {
  strings:
    $key_5891 = { 0b fe [2] 2f f0 [2] 04 dc [2] 2a fe [2] 3e e5 [2] 31 ff [2] 2f e2 [2] 2d e3 [2] 36 e5 [2] 2a e2 [2] 36 cd }

  condition:
    any of them
}