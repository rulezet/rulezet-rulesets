rule TTP_XOR_QUAD_CurrentVersionRun_00a2 {
  strings:
    $key_00a2 = { 53 cd [2] 77 c3 [2] 5c ef [2] 72 cd [2] 66 d6 [2] 69 cc [2] 77 d1 [2] 75 d0 [2] 6e d6 [2] 72 d1 [2] 6e fe }

  condition:
    any of them
}