rule TTP_XOR_QUAD_CurrentVersionRun_5e6d {
  strings:
    $key_5e6d = { 0d 02 [2] 29 0c [2] 02 20 [2] 2c 02 [2] 38 19 [2] 37 03 [2] 29 1e [2] 2b 1f [2] 30 19 [2] 2c 1e [2] 30 31 }

  condition:
    any of them
}