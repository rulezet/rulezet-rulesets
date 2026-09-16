rule TTP_XOR_QUAD_CurrentVersionRun_6e0e {
  strings:
    $key_6e0e = { 3d 61 [2] 19 6f [2] 32 43 [2] 1c 61 [2] 08 7a [2] 07 60 [2] 19 7d [2] 1b 7c [2] 00 7a [2] 1c 7d [2] 00 52 }

  condition:
    any of them
}