rule TTP_XOR_QUAD_CurrentVersionRun_ed53 {
  strings:
    $key_ed53 = { be 3c [2] 9a 32 [2] b1 1e [2] 9f 3c [2] 8b 27 [2] 84 3d [2] 9a 20 [2] 98 21 [2] 83 27 [2] 9f 20 [2] 83 0f }

  condition:
    any of them
}