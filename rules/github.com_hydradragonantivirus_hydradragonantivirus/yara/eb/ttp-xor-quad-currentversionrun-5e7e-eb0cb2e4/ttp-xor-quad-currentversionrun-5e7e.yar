rule TTP_XOR_QUAD_CurrentVersionRun_5e7e {
  strings:
    $key_5e7e = { 0d 11 [2] 29 1f [2] 02 33 [2] 2c 11 [2] 38 0a [2] 37 10 [2] 29 0d [2] 2b 0c [2] 30 0a [2] 2c 0d [2] 30 22 }

  condition:
    any of them
}