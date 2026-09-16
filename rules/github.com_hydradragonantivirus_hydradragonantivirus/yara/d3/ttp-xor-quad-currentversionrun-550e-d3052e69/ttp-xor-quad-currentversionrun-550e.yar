rule TTP_XOR_QUAD_CurrentVersionRun_550e {
  strings:
    $key_550e = { 06 61 [2] 22 6f [2] 09 43 [2] 27 61 [2] 33 7a [2] 3c 60 [2] 22 7d [2] 20 7c [2] 3b 7a [2] 27 7d [2] 3b 52 }

  condition:
    any of them
}