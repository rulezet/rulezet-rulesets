rule TTP_XOR_QUAD_CurrentVersionRun_60ee {
  strings:
    $key_60ee = { 33 81 [2] 17 8f [2] 3c a3 [2] 12 81 [2] 06 9a [2] 09 80 [2] 17 9d [2] 15 9c [2] 0e 9a [2] 12 9d [2] 0e b2 }

  condition:
    any of them
}