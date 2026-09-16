rule TTP_XOR_QUAD_CurrentVersionRun_426c {
  strings:
    $key_426c = { 11 03 [2] 35 0d [2] 1e 21 [2] 30 03 [2] 24 18 [2] 2b 02 [2] 35 1f [2] 37 1e [2] 2c 18 [2] 30 1f [2] 2c 30 }

  condition:
    any of them
}