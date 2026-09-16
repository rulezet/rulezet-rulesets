rule TTP_XOR_QUAD_CurrentVersionRun_a649 {
  strings:
    $key_a649 = { f5 26 [2] d1 28 [2] fa 04 [2] d4 26 [2] c0 3d [2] cf 27 [2] d1 3a [2] d3 3b [2] c8 3d [2] d4 3a [2] c8 15 }

  condition:
    any of them
}