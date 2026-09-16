rule TTP_XOR_QUAD_CurrentVersionRun_4053 {
  strings:
    $key_4053 = { 13 3c [2] 37 32 [2] 1c 1e [2] 32 3c [2] 26 27 [2] 29 3d [2] 37 20 [2] 35 21 [2] 2e 27 [2] 32 20 [2] 2e 0f }

  condition:
    any of them
}