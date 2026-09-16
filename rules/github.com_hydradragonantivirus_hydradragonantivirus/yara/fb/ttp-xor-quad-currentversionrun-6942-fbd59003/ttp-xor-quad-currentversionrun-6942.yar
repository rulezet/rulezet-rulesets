rule TTP_XOR_QUAD_CurrentVersionRun_6942 {
  strings:
    $key_6942 = { 3a 2d [2] 1e 23 [2] 35 0f [2] 1b 2d [2] 0f 36 [2] 00 2c [2] 1e 31 [2] 1c 30 [2] 07 36 [2] 1b 31 [2] 07 1e }

  condition:
    any of them
}