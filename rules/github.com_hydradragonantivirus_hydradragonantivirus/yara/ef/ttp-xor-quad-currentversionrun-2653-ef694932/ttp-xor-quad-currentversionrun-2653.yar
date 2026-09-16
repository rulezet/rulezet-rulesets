rule TTP_XOR_QUAD_CurrentVersionRun_2653 {
  strings:
    $key_2653 = { 75 3c [2] 51 32 [2] 7a 1e [2] 54 3c [2] 40 27 [2] 4f 3d [2] 51 20 [2] 53 21 [2] 48 27 [2] 54 20 [2] 48 0f }

  condition:
    any of them
}