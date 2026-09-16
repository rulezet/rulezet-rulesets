rule TTP_XOR_QUAD_CurrentVersionRun_69a3 {
  strings:
    $key_69a3 = { 3a cc [2] 1e c2 [2] 35 ee [2] 1b cc [2] 0f d7 [2] 00 cd [2] 1e d0 [2] 1c d1 [2] 07 d7 [2] 1b d0 [2] 07 ff }

  condition:
    any of them
}