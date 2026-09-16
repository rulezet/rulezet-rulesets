rule TTP_XOR_QUAD_CurrentVersionRun_710e {
  strings:
    $key_710e = { 22 61 [2] 06 6f [2] 2d 43 [2] 03 61 [2] 17 7a [2] 18 60 [2] 06 7d [2] 04 7c [2] 1f 7a [2] 03 7d [2] 1f 52 }

  condition:
    any of them
}