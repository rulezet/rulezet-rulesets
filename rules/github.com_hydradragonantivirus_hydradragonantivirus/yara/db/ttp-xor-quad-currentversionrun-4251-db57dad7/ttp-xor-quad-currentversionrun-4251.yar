rule TTP_XOR_QUAD_CurrentVersionRun_4251 {
  strings:
    $key_4251 = { 11 3e [2] 35 30 [2] 1e 1c [2] 30 3e [2] 24 25 [2] 2b 3f [2] 35 22 [2] 37 23 [2] 2c 25 [2] 30 22 [2] 2c 0d }

  condition:
    any of them
}