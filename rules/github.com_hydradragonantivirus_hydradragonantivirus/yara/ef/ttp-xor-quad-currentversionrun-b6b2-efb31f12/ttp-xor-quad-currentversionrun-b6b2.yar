rule TTP_XOR_QUAD_CurrentVersionRun_b6b2 {
  strings:
    $key_b6b2 = { e5 dd [2] c1 d3 [2] ea ff [2] c4 dd [2] d0 c6 [2] df dc [2] c1 c1 [2] c3 c0 [2] d8 c6 [2] c4 c1 [2] d8 ee }

  condition:
    any of them
}