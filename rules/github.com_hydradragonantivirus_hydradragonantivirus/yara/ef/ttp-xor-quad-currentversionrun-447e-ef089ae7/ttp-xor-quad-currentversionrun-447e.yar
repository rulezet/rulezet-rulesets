rule TTP_XOR_QUAD_CurrentVersionRun_447e {
  strings:
    $key_447e = { 17 11 [2] 33 1f [2] 18 33 [2] 36 11 [2] 22 0a [2] 2d 10 [2] 33 0d [2] 31 0c [2] 2a 0a [2] 36 0d [2] 2a 22 }

  condition:
    any of them
}