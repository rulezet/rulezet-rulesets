rule TTP_XOR_QUAD_CurrentVersionRun_423d {
  strings:
    $key_423d = { 11 52 [2] 35 5c [2] 1e 70 [2] 30 52 [2] 24 49 [2] 2b 53 [2] 35 4e [2] 37 4f [2] 2c 49 [2] 30 4e [2] 2c 61 }

  condition:
    any of them
}