rule TTP_XOR_QUAD_CurrentVersionRun_4a0e {
  strings:
    $key_4a0e = { 19 61 [2] 3d 6f [2] 16 43 [2] 38 61 [2] 2c 7a [2] 23 60 [2] 3d 7d [2] 3f 7c [2] 24 7a [2] 38 7d [2] 24 52 }

  condition:
    any of them
}