rule TTP_XOR_QUAD_CurrentVersionRun_4d0b {
  strings:
    $key_4d0b = { 1e 64 [2] 3a 6a [2] 11 46 [2] 3f 64 [2] 2b 7f [2] 24 65 [2] 3a 78 [2] 38 79 [2] 23 7f [2] 3f 78 [2] 23 57 }

  condition:
    any of them
}