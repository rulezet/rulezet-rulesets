rule TTP_XOR_QUAD_CurrentVersionRun_2161 {
  strings:
    $key_2161 = { 72 0e [2] 56 00 [2] 7d 2c [2] 53 0e [2] 47 15 [2] 48 0f [2] 56 12 [2] 54 13 [2] 4f 15 [2] 53 12 [2] 4f 3d }

  condition:
    any of them
}