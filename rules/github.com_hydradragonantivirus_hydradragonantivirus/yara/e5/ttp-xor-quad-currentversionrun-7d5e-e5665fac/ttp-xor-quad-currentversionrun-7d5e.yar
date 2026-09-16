rule TTP_XOR_QUAD_CurrentVersionRun_7d5e {
  strings:
    $key_7d5e = { 2e 31 [2] 0a 3f [2] 21 13 [2] 0f 31 [2] 1b 2a [2] 14 30 [2] 0a 2d [2] 08 2c [2] 13 2a [2] 0f 2d [2] 13 02 }

  condition:
    any of them
}