rule TTP_XOR_QUAD_CurrentVersionRun_42a2 {
  strings:
    $key_42a2 = { 11 cd [2] 35 c3 [2] 1e ef [2] 30 cd [2] 24 d6 [2] 2b cc [2] 35 d1 [2] 37 d0 [2] 2c d6 [2] 30 d1 [2] 2c fe }

  condition:
    any of them
}