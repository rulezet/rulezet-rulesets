rule TTP_XOR_QUAD_CurrentVersionRun_a1d2 {
  strings:
    $key_a1d2 = { f2 bd [2] d6 b3 [2] fd 9f [2] d3 bd [2] c7 a6 [2] c8 bc [2] d6 a1 [2] d4 a0 [2] cf a6 [2] d3 a1 [2] cf 8e }

  condition:
    any of them
}