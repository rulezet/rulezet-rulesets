rule TTP_XOR_QUAD_CurrentVersionRun_6c91 {
  strings:
    $key_6c91 = { 3f fe [2] 1b f0 [2] 30 dc [2] 1e fe [2] 0a e5 [2] 05 ff [2] 1b e2 [2] 19 e3 [2] 02 e5 [2] 1e e2 [2] 02 cd }

  condition:
    any of them
}