rule TTP_XOR_QUAD_CurrentVersionRun_1369 {
  strings:
    $key_1369 = { 40 06 [2] 64 08 [2] 4f 24 [2] 61 06 [2] 75 1d [2] 7a 07 [2] 64 1a [2] 66 1b [2] 7d 1d [2] 61 1a [2] 7d 35 }

  condition:
    any of them
}