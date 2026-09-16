rule TTP_XOR_QUAD_CurrentVersionRun_56b2 {
  strings:
    $key_56b2 = { 05 dd [2] 21 d3 [2] 0a ff [2] 24 dd [2] 30 c6 [2] 3f dc [2] 21 c1 [2] 23 c0 [2] 38 c6 [2] 24 c1 [2] 38 ee }

  condition:
    any of them
}