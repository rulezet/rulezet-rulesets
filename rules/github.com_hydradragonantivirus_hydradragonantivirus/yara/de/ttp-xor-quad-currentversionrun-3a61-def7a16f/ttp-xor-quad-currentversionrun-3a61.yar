rule TTP_XOR_QUAD_CurrentVersionRun_3a61 {
  strings:
    $key_3a61 = { 69 0e [2] 4d 00 [2] 66 2c [2] 48 0e [2] 5c 15 [2] 53 0f [2] 4d 12 [2] 4f 13 [2] 54 15 [2] 48 12 [2] 54 3d }

  condition:
    any of them
}