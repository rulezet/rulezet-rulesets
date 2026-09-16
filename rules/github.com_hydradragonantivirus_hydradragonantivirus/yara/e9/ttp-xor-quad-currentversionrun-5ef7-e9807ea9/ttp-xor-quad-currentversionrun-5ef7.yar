rule TTP_XOR_QUAD_CurrentVersionRun_5ef7 {
  strings:
    $key_5ef7 = { 0d 98 [2] 29 96 [2] 02 ba [2] 2c 98 [2] 38 83 [2] 37 99 [2] 29 84 [2] 2b 85 [2] 30 83 [2] 2c 84 [2] 30 ab }

  condition:
    any of them
}