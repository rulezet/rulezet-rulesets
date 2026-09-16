rule TTP_XOR_QUAD_CurrentVersionRun_2e91 {
  strings:
    $key_2e91 = { 7d fe [2] 59 f0 [2] 72 dc [2] 5c fe [2] 48 e5 [2] 47 ff [2] 59 e2 [2] 5b e3 [2] 40 e5 [2] 5c e2 [2] 40 cd }

  condition:
    any of them
}