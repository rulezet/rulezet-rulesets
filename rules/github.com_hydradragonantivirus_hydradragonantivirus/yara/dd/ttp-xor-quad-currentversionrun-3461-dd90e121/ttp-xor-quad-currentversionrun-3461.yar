rule TTP_XOR_QUAD_CurrentVersionRun_3461 {
  strings:
    $key_3461 = { 67 0e [2] 43 00 [2] 68 2c [2] 46 0e [2] 52 15 [2] 5d 0f [2] 43 12 [2] 41 13 [2] 5a 15 [2] 46 12 [2] 5a 3d }

  condition:
    any of them
}