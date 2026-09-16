rule TTP_XOR_QUAD_CurrentVersionRun_e3b2 {
  strings:
    $key_e3b2 = { b0 dd [2] 94 d3 [2] bf ff [2] 91 dd [2] 85 c6 [2] 8a dc [2] 94 c1 [2] 96 c0 [2] 8d c6 [2] 91 c1 [2] 8d ee }

  condition:
    any of them
}