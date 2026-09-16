rule TTP_XOR_QUAD_CurrentVersionRun_0c91 {
  strings:
    $key_0c91 = { 5f fe [2] 7b f0 [2] 50 dc [2] 7e fe [2] 6a e5 [2] 65 ff [2] 7b e2 [2] 79 e3 [2] 62 e5 [2] 7e e2 [2] 62 cd }

  condition:
    any of them
}