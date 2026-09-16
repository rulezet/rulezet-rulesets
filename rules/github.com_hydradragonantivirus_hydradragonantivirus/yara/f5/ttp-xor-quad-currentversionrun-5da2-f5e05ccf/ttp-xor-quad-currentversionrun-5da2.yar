rule TTP_XOR_QUAD_CurrentVersionRun_5da2 {
  strings:
    $key_5da2 = { 0e cd [2] 2a c3 [2] 01 ef [2] 2f cd [2] 3b d6 [2] 34 cc [2] 2a d1 [2] 28 d0 [2] 33 d6 [2] 2f d1 [2] 33 fe }

  condition:
    any of them
}