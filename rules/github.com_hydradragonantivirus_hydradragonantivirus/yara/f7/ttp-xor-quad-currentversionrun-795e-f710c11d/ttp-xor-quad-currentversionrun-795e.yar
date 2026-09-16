rule TTP_XOR_QUAD_CurrentVersionRun_795e {
  strings:
    $key_795e = { 2a 31 [2] 0e 3f [2] 25 13 [2] 0b 31 [2] 1f 2a [2] 10 30 [2] 0e 2d [2] 0c 2c [2] 17 2a [2] 0b 2d [2] 17 02 }

  condition:
    any of them
}