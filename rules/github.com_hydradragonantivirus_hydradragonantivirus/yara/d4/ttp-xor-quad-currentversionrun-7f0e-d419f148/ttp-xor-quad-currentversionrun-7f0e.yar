rule TTP_XOR_QUAD_CurrentVersionRun_7f0e {
  strings:
    $key_7f0e = { 2c 61 [2] 08 6f [2] 23 43 [2] 0d 61 [2] 19 7a [2] 16 60 [2] 08 7d [2] 0a 7c [2] 11 7a [2] 0d 7d [2] 11 52 }

  condition:
    any of them
}