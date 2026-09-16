rule TTP_XOR_QUAD_CurrentVersionRun_b353 {
  strings:
    $key_b353 = { e0 3c [2] c4 32 [2] ef 1e [2] c1 3c [2] d5 27 [2] da 3d [2] c4 20 [2] c6 21 [2] dd 27 [2] c1 20 [2] dd 0f }

  condition:
    any of them
}