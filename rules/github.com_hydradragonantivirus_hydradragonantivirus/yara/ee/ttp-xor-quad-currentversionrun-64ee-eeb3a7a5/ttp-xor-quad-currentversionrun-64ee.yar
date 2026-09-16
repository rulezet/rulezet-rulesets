rule TTP_XOR_QUAD_CurrentVersionRun_64ee {
  strings:
    $key_64ee = { 37 81 [2] 13 8f [2] 38 a3 [2] 16 81 [2] 02 9a [2] 0d 80 [2] 13 9d [2] 11 9c [2] 0a 9a [2] 16 9d [2] 0a b2 }

  condition:
    any of them
}