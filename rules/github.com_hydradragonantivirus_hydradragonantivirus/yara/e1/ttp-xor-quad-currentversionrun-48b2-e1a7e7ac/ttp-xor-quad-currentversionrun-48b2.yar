rule TTP_XOR_QUAD_CurrentVersionRun_48b2 {
  strings:
    $key_48b2 = { 1b dd [2] 3f d3 [2] 14 ff [2] 3a dd [2] 2e c6 [2] 21 dc [2] 3f c1 [2] 3d c0 [2] 26 c6 [2] 3a c1 [2] 26 ee }

  condition:
    any of them
}