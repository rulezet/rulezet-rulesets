rule TTP_XOR_QUAD_CurrentVersionRun_7d91 {
  strings:
    $key_7d91 = { 2e fe [2] 0a f0 [2] 21 dc [2] 0f fe [2] 1b e5 [2] 14 ff [2] 0a e2 [2] 08 e3 [2] 13 e5 [2] 0f e2 [2] 13 cd }

  condition:
    any of them
}