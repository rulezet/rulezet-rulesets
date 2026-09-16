rule TTP_XOR_QUAD_CurrentVersionRun_a1b3 {
  strings:
    $key_a1b3 = { f2 dc [2] d6 d2 [2] fd fe [2] d3 dc [2] c7 c7 [2] c8 dd [2] d6 c0 [2] d4 c1 [2] cf c7 [2] d3 c0 [2] cf ef }

  condition:
    any of them
}