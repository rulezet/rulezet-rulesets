rule TTP_XOR_QUAD_CurrentVersionRun_53eb {
  strings:
    $key_53eb = { 00 84 [2] 24 8a [2] 0f a6 [2] 21 84 [2] 35 9f [2] 3a 85 [2] 24 98 [2] 26 99 [2] 3d 9f [2] 21 98 [2] 3d b7 }

  condition:
    any of them
}