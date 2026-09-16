rule TTP_XOR_QUAD_CurrentVersionRun_427c {
  strings:
    $key_427c = { 11 13 [2] 35 1d [2] 1e 31 [2] 30 13 [2] 24 08 [2] 2b 12 [2] 35 0f [2] 37 0e [2] 2c 08 [2] 30 0f [2] 2c 20 }

  condition:
    any of them
}