rule TTP_XOR_QUAD_CurrentVersionRun_3127 {
  strings:
    $key_3127 = { 62 48 [2] 46 46 [2] 6d 6a [2] 43 48 [2] 57 53 [2] 58 49 [2] 46 54 [2] 44 55 [2] 5f 53 [2] 43 54 [2] 5f 7b }

  condition:
    any of them
}