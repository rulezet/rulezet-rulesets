rule TTP_XOR_QUAD_CurrentVersionRun_47a2 {
  strings:
    $key_47a2 = { 14 cd [2] 30 c3 [2] 1b ef [2] 35 cd [2] 21 d6 [2] 2e cc [2] 30 d1 [2] 32 d0 [2] 29 d6 [2] 35 d1 [2] 29 fe }

  condition:
    any of them
}