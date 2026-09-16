rule TTP_XOR_QUAD_CurrentVersionRun_5f41 {
  strings:
    $key_5f41 = { 0c 2e [2] 28 20 [2] 03 0c [2] 2d 2e [2] 39 35 [2] 36 2f [2] 28 32 [2] 2a 33 [2] 31 35 [2] 2d 32 [2] 31 1d }

  condition:
    any of them
}