rule TTP_XOR_QUAD_CurrentVersionRun_420e {
  strings:
    $key_420e = { 11 61 [2] 35 6f [2] 1e 43 [2] 30 61 [2] 24 7a [2] 2b 60 [2] 35 7d [2] 37 7c [2] 2c 7a [2] 30 7d [2] 2c 52 }

  condition:
    any of them
}