rule TTP_XOR_QUAD_CurrentVersionRun_6ca2 {
  strings:
    $key_6ca2 = { 3f cd [2] 1b c3 [2] 30 ef [2] 1e cd [2] 0a d6 [2] 05 cc [2] 1b d1 [2] 19 d0 [2] 02 d6 [2] 1e d1 [2] 02 fe }

  condition:
    any of them
}