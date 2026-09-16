rule TTP_XOR_QUAD_CurrentVersionRun_3c61 {
  strings:
    $key_3c61 = { 6f 0e [2] 4b 00 [2] 60 2c [2] 4e 0e [2] 5a 15 [2] 55 0f [2] 4b 12 [2] 49 13 [2] 52 15 [2] 4e 12 [2] 52 3d }

  condition:
    any of them
}