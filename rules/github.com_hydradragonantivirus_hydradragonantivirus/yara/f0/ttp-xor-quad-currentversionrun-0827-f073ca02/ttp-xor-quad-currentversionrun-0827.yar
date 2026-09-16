rule TTP_XOR_QUAD_CurrentVersionRun_0827 {
  strings:
    $key_0827 = { 5b 48 [2] 7f 46 [2] 54 6a [2] 7a 48 [2] 6e 53 [2] 61 49 [2] 7f 54 [2] 7d 55 [2] 66 53 [2] 7a 54 [2] 66 7b }

  condition:
    any of them
}