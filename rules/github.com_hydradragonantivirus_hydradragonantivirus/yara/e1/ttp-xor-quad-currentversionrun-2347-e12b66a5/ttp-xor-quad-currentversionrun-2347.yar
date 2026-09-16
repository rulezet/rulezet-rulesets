rule TTP_XOR_QUAD_CurrentVersionRun_2347 {
  strings:
    $key_2347 = { 70 28 [2] 54 26 [2] 7f 0a [2] 51 28 [2] 45 33 [2] 4a 29 [2] 54 34 [2] 56 35 [2] 4d 33 [2] 51 34 [2] 4d 1b }

  condition:
    any of them
}