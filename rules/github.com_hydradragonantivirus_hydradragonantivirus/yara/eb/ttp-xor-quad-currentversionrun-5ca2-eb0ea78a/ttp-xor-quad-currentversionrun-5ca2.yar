rule TTP_XOR_QUAD_CurrentVersionRun_5ca2 {
  strings:
    $key_5ca2 = { 0f cd [2] 2b c3 [2] 00 ef [2] 2e cd [2] 3a d6 [2] 35 cc [2] 2b d1 [2] 29 d0 [2] 32 d6 [2] 2e d1 [2] 32 fe }

  condition:
    any of them
}