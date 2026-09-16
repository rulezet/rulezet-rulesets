rule TTP_XOR_QUAD_CurrentVersionRun_0327 {
  strings:
    $key_0327 = { 50 48 [2] 74 46 [2] 5f 6a [2] 71 48 [2] 65 53 [2] 6a 49 [2] 74 54 [2] 76 55 [2] 6d 53 [2] 71 54 [2] 6d 7b }

  condition:
    any of them
}