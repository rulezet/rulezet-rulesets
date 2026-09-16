rule TTP_XOR_QUAD_CurrentVersionRun_7b27 {
  strings:
    $key_7b27 = { 28 48 [2] 0c 46 [2] 27 6a [2] 09 48 [2] 1d 53 [2] 12 49 [2] 0c 54 [2] 0e 55 [2] 15 53 [2] 09 54 [2] 15 7b }

  condition:
    any of them
}