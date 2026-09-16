rule TTP_XOR_QUAD_CurrentVersionRun_7827 {
  strings:
    $key_7827 = { 2b 48 [2] 0f 46 [2] 24 6a [2] 0a 48 [2] 1e 53 [2] 11 49 [2] 0f 54 [2] 0d 55 [2] 16 53 [2] 0a 54 [2] 16 7b }

  condition:
    any of them
}