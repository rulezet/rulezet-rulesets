rule TTP_XOR_QUAD_CurrentVersionRun_457e {
  strings:
    $key_457e = { 16 11 [2] 32 1f [2] 19 33 [2] 37 11 [2] 23 0a [2] 2c 10 [2] 32 0d [2] 30 0c [2] 2b 0a [2] 37 0d [2] 2b 22 }

  condition:
    any of them
}