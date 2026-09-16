rule TTP_XOR_QUAD_CurrentVersionRun_774e {
  strings:
    $key_774e = { 24 21 [2] 00 2f [2] 2b 03 [2] 05 21 [2] 11 3a [2] 1e 20 [2] 00 3d [2] 02 3c [2] 19 3a [2] 05 3d [2] 19 12 }

  condition:
    any of them
}