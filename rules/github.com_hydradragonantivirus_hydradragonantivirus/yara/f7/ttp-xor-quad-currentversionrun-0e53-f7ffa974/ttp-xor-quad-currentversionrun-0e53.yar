rule TTP_XOR_QUAD_CurrentVersionRun_0e53 {
  strings:
    $key_0e53 = { 5d 3c [2] 79 32 [2] 52 1e [2] 7c 3c [2] 68 27 [2] 67 3d [2] 79 20 [2] 7b 21 [2] 60 27 [2] 7c 20 [2] 60 0f }

  condition:
    any of them
}