rule TTP_XOR_QUAD_CurrentVersionRun_4042 {
  strings:
    $key_4042 = { 13 2d [2] 37 23 [2] 1c 0f [2] 32 2d [2] 26 36 [2] 29 2c [2] 37 31 [2] 35 30 [2] 2e 36 [2] 32 31 [2] 2e 1e }

  condition:
    any of them
}