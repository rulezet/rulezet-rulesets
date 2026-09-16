rule TTP_XOR_QUAD_CurrentVersionRun_6427 {
  strings:
    $key_6427 = { 37 48 [2] 13 46 [2] 38 6a [2] 16 48 [2] 02 53 [2] 0d 49 [2] 13 54 [2] 11 55 [2] 0a 53 [2] 16 54 [2] 0a 7b }

  condition:
    any of them
}