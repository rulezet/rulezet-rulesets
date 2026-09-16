rule TTP_XOR_QUAD_CurrentVersionRun_29b2 {
  strings:
    $key_29b2 = { 7a dd [2] 5e d3 [2] 75 ff [2] 5b dd [2] 4f c6 [2] 40 dc [2] 5e c1 [2] 5c c0 [2] 47 c6 [2] 5b c1 [2] 47 ee }

  condition:
    any of them
}