rule TTP_XOR_QUAD_CurrentVersionRun_fb53 {
  strings:
    $key_fb53 = { a8 3c [2] 8c 32 [2] a7 1e [2] 89 3c [2] 9d 27 [2] 92 3d [2] 8c 20 [2] 8e 21 [2] 95 27 [2] 89 20 [2] 95 0f }

  condition:
    any of them
}