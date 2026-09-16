rule TTP_XOR_QUAD_CurrentVersionRun_423c {
  strings:
    $key_423c = { 11 53 [2] 35 5d [2] 1e 71 [2] 30 53 [2] 24 48 [2] 2b 52 [2] 35 4f [2] 37 4e [2] 2c 48 [2] 30 4f [2] 2c 60 }

  condition:
    any of them
}