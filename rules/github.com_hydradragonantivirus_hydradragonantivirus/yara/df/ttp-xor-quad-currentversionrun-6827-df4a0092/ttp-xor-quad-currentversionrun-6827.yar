rule TTP_XOR_QUAD_CurrentVersionRun_6827 {
  strings:
    $key_6827 = { 3b 48 [2] 1f 46 [2] 34 6a [2] 1a 48 [2] 0e 53 [2] 01 49 [2] 1f 54 [2] 1d 55 [2] 06 53 [2] 1a 54 [2] 06 7b }

  condition:
    any of them
}