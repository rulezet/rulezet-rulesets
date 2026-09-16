rule TTP_XOR_QUAD_CurrentVersionRun_4202 {
  strings:
    $key_4202 = { 11 6d [2] 35 63 [2] 1e 4f [2] 30 6d [2] 24 76 [2] 2b 6c [2] 35 71 [2] 37 70 [2] 2c 76 [2] 30 71 [2] 2c 5e }

  condition:
    any of them
}