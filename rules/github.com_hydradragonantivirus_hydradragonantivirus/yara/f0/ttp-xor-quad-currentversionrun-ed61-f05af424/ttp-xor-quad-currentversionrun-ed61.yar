rule TTP_XOR_QUAD_CurrentVersionRun_ed61 {
  strings:
    $key_ed61 = { be 0e [2] 9a 00 [2] b1 2c [2] 9f 0e [2] 8b 15 [2] 84 0f [2] 9a 12 [2] 98 13 [2] 83 15 [2] 9f 12 [2] 83 3d }

  condition:
    any of them
}