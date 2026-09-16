rule TTP_XOR_QUAD_CurrentVersionRun_5e42 {
  strings:
    $key_5e42 = { 0d 2d [2] 29 23 [2] 02 0f [2] 2c 2d [2] 38 36 [2] 37 2c [2] 29 31 [2] 2b 30 [2] 30 36 [2] 2c 31 [2] 30 1e }

  condition:
    any of them
}