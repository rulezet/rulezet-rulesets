rule TTP_XOR_QUAD_CurrentVersionRun_5526 {
  strings:
    $key_5526 = { 06 49 [2] 22 47 [2] 09 6b [2] 27 49 [2] 33 52 [2] 3c 48 [2] 22 55 [2] 20 54 [2] 3b 52 [2] 27 55 [2] 3b 7a }

  condition:
    any of them
}