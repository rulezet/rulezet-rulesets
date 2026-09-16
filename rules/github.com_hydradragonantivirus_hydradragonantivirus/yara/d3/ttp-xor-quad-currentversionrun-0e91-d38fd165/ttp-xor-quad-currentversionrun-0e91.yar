rule TTP_XOR_QUAD_CurrentVersionRun_0e91 {
  strings:
    $key_0e91 = { 5d fe [2] 79 f0 [2] 52 dc [2] 7c fe [2] 68 e5 [2] 67 ff [2] 79 e2 [2] 7b e3 [2] 60 e5 [2] 7c e2 [2] 60 cd }

  condition:
    any of them
}