rule TTP_XOR_QUAD_CurrentVersionRun_06b2 {
  strings:
    $key_06b2 = { 55 dd [2] 71 d3 [2] 5a ff [2] 74 dd [2] 60 c6 [2] 6f dc [2] 71 c1 [2] 73 c0 [2] 68 c6 [2] 74 c1 [2] 68 ee }

  condition:
    any of them
}