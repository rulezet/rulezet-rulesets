rule TTP_XOR_QUAD_CurrentVersionRun_2753 {
  strings:
    $key_2753 = { 74 3c [2] 50 32 [2] 7b 1e [2] 55 3c [2] 41 27 [2] 4e 3d [2] 50 20 [2] 52 21 [2] 49 27 [2] 55 20 [2] 49 0f }

  condition:
    any of them
}