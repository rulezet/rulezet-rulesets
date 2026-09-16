rule TTP_XOR_QUAD_CurrentVersionRun_665e {
  strings:
    $key_665e = { 35 31 [2] 11 3f [2] 3a 13 [2] 14 31 [2] 00 2a [2] 0f 30 [2] 11 2d [2] 13 2c [2] 08 2a [2] 14 2d [2] 08 02 }

  condition:
    any of them
}