rule TTP_XOR_QUAD_CurrentVersionRun_3653 {
  strings:
    $key_3653 = { 65 3c [2] 41 32 [2] 6a 1e [2] 44 3c [2] 50 27 [2] 5f 3d [2] 41 20 [2] 43 21 [2] 58 27 [2] 44 20 [2] 58 0f }

  condition:
    any of them
}