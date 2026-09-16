rule TTP_XOR_QUAD_CurrentVersionRun_09b2 {
  strings:
    $key_09b2 = { 5a dd [2] 7e d3 [2] 55 ff [2] 7b dd [2] 6f c6 [2] 60 dc [2] 7e c1 [2] 7c c0 [2] 67 c6 [2] 7b c1 [2] 67 ee }

  condition:
    any of them
}