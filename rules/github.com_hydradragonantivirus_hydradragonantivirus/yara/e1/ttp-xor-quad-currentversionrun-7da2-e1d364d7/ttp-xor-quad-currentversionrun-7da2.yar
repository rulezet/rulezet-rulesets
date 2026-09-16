rule TTP_XOR_QUAD_CurrentVersionRun_7da2 {
  strings:
    $key_7da2 = { 2e cd [2] 0a c3 [2] 21 ef [2] 0f cd [2] 1b d6 [2] 14 cc [2] 0a d1 [2] 08 d0 [2] 13 d6 [2] 0f d1 [2] 13 fe }

  condition:
    any of them
}