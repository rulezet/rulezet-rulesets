rule TTP_XOR_QUAD_CurrentVersionRun_4aea {
  strings:
    $key_4aea = { 19 85 [2] 3d 8b [2] 16 a7 [2] 38 85 [2] 2c 9e [2] 23 84 [2] 3d 99 [2] 3f 98 [2] 24 9e [2] 38 99 [2] 24 b6 }

  condition:
    any of them
}