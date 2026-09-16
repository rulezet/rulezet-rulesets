rule TTP_XOR_QUAD_CurrentVersionRun_5a0e {
  strings:
    $key_5a0e = { 09 61 [2] 2d 6f [2] 06 43 [2] 28 61 [2] 3c 7a [2] 33 60 [2] 2d 7d [2] 2f 7c [2] 34 7a [2] 28 7d [2] 34 52 }

  condition:
    any of them
}