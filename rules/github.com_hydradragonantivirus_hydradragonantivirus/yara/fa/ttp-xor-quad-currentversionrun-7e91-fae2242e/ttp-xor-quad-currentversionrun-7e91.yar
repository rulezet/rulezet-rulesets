rule TTP_XOR_QUAD_CurrentVersionRun_7e91 {
  strings:
    $key_7e91 = { 2d fe [2] 09 f0 [2] 22 dc [2] 0c fe [2] 18 e5 [2] 17 ff [2] 09 e2 [2] 0b e3 [2] 10 e5 [2] 0c e2 [2] 10 cd }

  condition:
    any of them
}