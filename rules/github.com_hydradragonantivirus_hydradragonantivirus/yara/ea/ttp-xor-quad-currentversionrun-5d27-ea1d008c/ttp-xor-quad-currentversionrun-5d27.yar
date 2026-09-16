rule TTP_XOR_QUAD_CurrentVersionRun_5d27 {
  strings:
    $key_5d27 = { 0e 48 [2] 2a 46 [2] 01 6a [2] 2f 48 [2] 3b 53 [2] 34 49 [2] 2a 54 [2] 28 55 [2] 33 53 [2] 2f 54 [2] 33 7b }

  condition:
    any of them
}