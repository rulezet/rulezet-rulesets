rule TTP_XOR_QUAD_CurrentVersionRun_a1d0 {
  strings:
    $key_a1d0 = { f2 bf [2] d6 b1 [2] fd 9d [2] d3 bf [2] c7 a4 [2] c8 be [2] d6 a3 [2] d4 a2 [2] cf a4 [2] d3 a3 [2] cf 8c }

  condition:
    any of them
}