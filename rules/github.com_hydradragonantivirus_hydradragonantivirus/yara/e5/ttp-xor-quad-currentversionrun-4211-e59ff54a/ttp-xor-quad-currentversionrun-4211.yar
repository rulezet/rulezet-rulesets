rule TTP_XOR_QUAD_CurrentVersionRun_4211 {
  strings:
    $key_4211 = { 11 7e [2] 35 70 [2] 1e 5c [2] 30 7e [2] 24 65 [2] 2b 7f [2] 35 62 [2] 37 63 [2] 2c 65 [2] 30 62 [2] 2c 4d }

  condition:
    any of them
}