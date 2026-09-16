rule TTP_XOR_QUAD_CurrentVersionRun_3c5e {
  strings:
    $key_3c5e = { 6f 31 [2] 4b 3f [2] 60 13 [2] 4e 31 [2] 5a 2a [2] 55 30 [2] 4b 2d [2] 49 2c [2] 52 2a [2] 4e 2d [2] 52 02 }

  condition:
    any of them
}