rule TTP_XOR_QUAD_CurrentVersionRun_5b0e {
  strings:
    $key_5b0e = { 08 61 [2] 2c 6f [2] 07 43 [2] 29 61 [2] 3d 7a [2] 32 60 [2] 2c 7d [2] 2e 7c [2] 35 7a [2] 29 7d [2] 35 52 }

  condition:
    any of them
}