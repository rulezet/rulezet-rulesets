rule TTP_XOR_QUAD_CurrentVersionRun_0661 {
  strings:
    $key_0661 = { 55 0e [2] 71 00 [2] 5a 2c [2] 74 0e [2] 60 15 [2] 6f 0f [2] 71 12 [2] 73 13 [2] 68 15 [2] 74 12 [2] 68 3d }

  condition:
    any of them
}