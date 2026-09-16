rule TTP_XOR_QUAD_CurrentVersionRun_5b21 {
  strings:
    $key_5b21 = { 08 4e [2] 2c 40 [2] 07 6c [2] 29 4e [2] 3d 55 [2] 32 4f [2] 2c 52 [2] 2e 53 [2] 35 55 [2] 29 52 [2] 35 7d }

  condition:
    any of them
}