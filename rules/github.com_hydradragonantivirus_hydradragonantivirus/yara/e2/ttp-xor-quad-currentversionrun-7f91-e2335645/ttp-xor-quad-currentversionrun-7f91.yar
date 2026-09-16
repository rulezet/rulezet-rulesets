rule TTP_XOR_QUAD_CurrentVersionRun_7f91 {
  strings:
    $key_7f91 = { 2c fe [2] 08 f0 [2] 23 dc [2] 0d fe [2] 19 e5 [2] 16 ff [2] 08 e2 [2] 0a e3 [2] 11 e5 [2] 0d e2 [2] 11 cd }

  condition:
    any of them
}