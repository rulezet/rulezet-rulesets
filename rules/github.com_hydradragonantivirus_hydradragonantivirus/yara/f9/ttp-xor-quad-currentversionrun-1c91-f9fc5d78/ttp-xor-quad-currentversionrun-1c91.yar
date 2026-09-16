rule TTP_XOR_QUAD_CurrentVersionRun_1c91 {
  strings:
    $key_1c91 = { 4f fe [2] 6b f0 [2] 40 dc [2] 6e fe [2] 7a e5 [2] 75 ff [2] 6b e2 [2] 69 e3 [2] 72 e5 [2] 6e e2 [2] 72 cd }

  condition:
    any of them
}