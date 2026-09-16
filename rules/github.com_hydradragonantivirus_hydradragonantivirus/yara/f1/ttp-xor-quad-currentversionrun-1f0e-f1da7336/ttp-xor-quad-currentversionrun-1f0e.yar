rule TTP_XOR_QUAD_CurrentVersionRun_1f0e {
  strings:
    $key_1f0e = { 4c 61 [2] 68 6f [2] 43 43 [2] 6d 61 [2] 79 7a [2] 76 60 [2] 68 7d [2] 6a 7c [2] 71 7a [2] 6d 7d [2] 71 52 }

  condition:
    any of them
}