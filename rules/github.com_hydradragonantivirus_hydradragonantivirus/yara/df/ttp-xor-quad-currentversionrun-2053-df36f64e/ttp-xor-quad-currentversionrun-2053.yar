rule TTP_XOR_QUAD_CurrentVersionRun_2053 {
  strings:
    $key_2053 = { 73 3c [2] 57 32 [2] 7c 1e [2] 52 3c [2] 46 27 [2] 49 3d [2] 57 20 [2] 55 21 [2] 4e 27 [2] 52 20 [2] 4e 0f }

  condition:
    any of them
}