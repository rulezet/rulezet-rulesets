rule TTP_XOR_QUAD_CurrentVersionRun_2c91 {
  strings:
    $key_2c91 = { 7f fe [2] 5b f0 [2] 70 dc [2] 5e fe [2] 4a e5 [2] 45 ff [2] 5b e2 [2] 59 e3 [2] 42 e5 [2] 5e e2 [2] 42 cd }

  condition:
    any of them
}