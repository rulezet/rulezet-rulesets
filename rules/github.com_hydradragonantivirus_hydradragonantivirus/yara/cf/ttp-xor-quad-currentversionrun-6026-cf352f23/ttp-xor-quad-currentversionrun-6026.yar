rule TTP_XOR_QUAD_CurrentVersionRun_6026 {
  strings:
    $key_6026 = { 33 49 [2] 17 47 [2] 3c 6b [2] 12 49 [2] 06 52 [2] 09 48 [2] 17 55 [2] 15 54 [2] 0e 52 [2] 12 55 [2] 0e 7a }

  condition:
    any of them
}