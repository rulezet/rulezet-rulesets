rule TTP_XOR_QUAD_CurrentVersionRun_424f {
  strings:
    $key_424f = { 11 20 [2] 35 2e [2] 1e 02 [2] 30 20 [2] 24 3b [2] 2b 21 [2] 35 3c [2] 37 3d [2] 2c 3b [2] 30 3c [2] 2c 13 }

  condition:
    any of them
}