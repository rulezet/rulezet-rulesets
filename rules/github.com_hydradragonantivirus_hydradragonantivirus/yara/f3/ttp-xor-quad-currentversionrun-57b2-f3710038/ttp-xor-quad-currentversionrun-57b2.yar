rule TTP_XOR_QUAD_CurrentVersionRun_57b2 {
  strings:
    $key_57b2 = { 04 dd [2] 20 d3 [2] 0b ff [2] 25 dd [2] 31 c6 [2] 3e dc [2] 20 c1 [2] 22 c0 [2] 39 c6 [2] 25 c1 [2] 39 ee }

  condition:
    any of them
}