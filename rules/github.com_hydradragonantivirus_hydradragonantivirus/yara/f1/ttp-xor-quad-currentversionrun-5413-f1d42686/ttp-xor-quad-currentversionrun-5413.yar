rule TTP_XOR_QUAD_CurrentVersionRun_5413 {
  strings:
    $key_5413 = { 07 7c [2] 23 72 [2] 08 5e [2] 26 7c [2] 32 67 [2] 3d 7d [2] 23 60 [2] 21 61 [2] 3a 67 [2] 26 60 [2] 3a 4f }

  condition:
    any of them
}