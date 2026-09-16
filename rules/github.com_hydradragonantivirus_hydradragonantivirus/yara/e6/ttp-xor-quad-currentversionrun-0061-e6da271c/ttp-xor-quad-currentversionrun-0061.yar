rule TTP_XOR_QUAD_CurrentVersionRun_0061 {
  strings:
    $key_0061 = { 53 0e [2] 77 00 [2] 5c 2c [2] 72 0e [2] 66 15 [2] 69 0f [2] 77 12 [2] 75 13 [2] 6e 15 [2] 72 12 [2] 6e 3d }

  condition:
    any of them
}