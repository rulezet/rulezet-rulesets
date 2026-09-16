rule TTP_XOR_QUAD_CurrentVersionRun_1da2 {
  strings:
    $key_1da2 = { 4e cd [2] 6a c3 [2] 41 ef [2] 6f cd [2] 7b d6 [2] 74 cc [2] 6a d1 [2] 68 d0 [2] 73 d6 [2] 6f d1 [2] 73 fe }

  condition:
    any of them
}