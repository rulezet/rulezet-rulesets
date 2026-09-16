rule TTP_XOR_QUAD_CurrentVersionRun_ea53 {
  strings:
    $key_ea53 = { b9 3c [2] 9d 32 [2] b6 1e [2] 98 3c [2] 8c 27 [2] 83 3d [2] 9d 20 [2] 9f 21 [2] 84 27 [2] 98 20 [2] 84 0f }

  condition:
    any of them
}