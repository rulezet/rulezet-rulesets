rule TTP_XOR_QUAD_CurrentVersionRun_5ef6 {
  strings:
    $key_5ef6 = { 0d 99 [2] 29 97 [2] 02 bb [2] 2c 99 [2] 38 82 [2] 37 98 [2] 29 85 [2] 2b 84 [2] 30 82 [2] 2c 85 [2] 30 aa }

  condition:
    any of them
}