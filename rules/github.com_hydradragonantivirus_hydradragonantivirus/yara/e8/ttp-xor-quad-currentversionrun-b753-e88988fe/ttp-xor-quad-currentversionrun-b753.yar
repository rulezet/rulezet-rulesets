rule TTP_XOR_QUAD_CurrentVersionRun_b753 {
  strings:
    $key_b753 = { e4 3c [2] c0 32 [2] eb 1e [2] c5 3c [2] d1 27 [2] de 3d [2] c0 20 [2] c2 21 [2] d9 27 [2] c5 20 [2] d9 0f }

  condition:
    any of them
}