rule TTP_XOR_QUAD_CurrentVersionRun_a6d1 {
  strings:
    $key_a6d1 = { f5 be [2] d1 b0 [2] fa 9c [2] d4 be [2] c0 a5 [2] cf bf [2] d1 a2 [2] d3 a3 [2] c8 a5 [2] d4 a2 [2] c8 8d }

  condition:
    any of them
}