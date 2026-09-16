rule TTP_XOR_QUAD_CurrentVersionRun_4afd {
  strings:
    $key_4afd = { 19 92 [2] 3d 9c [2] 16 b0 [2] 38 92 [2] 2c 89 [2] 23 93 [2] 3d 8e [2] 3f 8f [2] 24 89 [2] 38 8e [2] 24 a1 }

  condition:
    any of them
}