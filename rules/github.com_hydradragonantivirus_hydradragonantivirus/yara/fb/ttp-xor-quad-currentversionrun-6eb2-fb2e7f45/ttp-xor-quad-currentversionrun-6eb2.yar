rule TTP_XOR_QUAD_CurrentVersionRun_6eb2 {
  strings:
    $key_6eb2 = { 3d dd [2] 19 d3 [2] 32 ff [2] 1c dd [2] 08 c6 [2] 07 dc [2] 19 c1 [2] 1b c0 [2] 00 c6 [2] 1c c1 [2] 00 ee }

  condition:
    any of them
}