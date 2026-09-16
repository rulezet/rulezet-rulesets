rule TTP_XOR_QUAD_CurrentVersionRun_6f91 {
  strings:
    $key_6f91 = { 3c fe [2] 18 f0 [2] 33 dc [2] 1d fe [2] 09 e5 [2] 06 ff [2] 18 e2 [2] 1a e3 [2] 01 e5 [2] 1d e2 [2] 01 cd }

  condition:
    any of them
}