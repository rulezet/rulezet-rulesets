rule TTP_XOR_QUAD_CurrentVersionRun_3261 {
  strings:
    $key_3261 = { 61 0e [2] 45 00 [2] 6e 2c [2] 40 0e [2] 54 15 [2] 5b 0f [2] 45 12 [2] 47 13 [2] 5c 15 [2] 40 12 [2] 5c 3d }

  condition:
    any of them
}