rule TTP_XOR_QUAD_CurrentVersionRun_3353 {
  strings:
    $key_3353 = { 60 3c [2] 44 32 [2] 6f 1e [2] 41 3c [2] 55 27 [2] 5a 3d [2] 44 20 [2] 46 21 [2] 5d 27 [2] 41 20 [2] 5d 0f }

  condition:
    any of them
}