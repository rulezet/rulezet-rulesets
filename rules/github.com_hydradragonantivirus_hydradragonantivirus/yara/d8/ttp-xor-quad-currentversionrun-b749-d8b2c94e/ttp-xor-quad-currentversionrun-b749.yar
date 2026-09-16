rule TTP_XOR_QUAD_CurrentVersionRun_b749 {
  strings:
    $key_b749 = { e4 26 [2] c0 28 [2] eb 04 [2] c5 26 [2] d1 3d [2] de 27 [2] c0 3a [2] c2 3b [2] d9 3d [2] c5 3a [2] d9 15 }

  condition:
    any of them
}