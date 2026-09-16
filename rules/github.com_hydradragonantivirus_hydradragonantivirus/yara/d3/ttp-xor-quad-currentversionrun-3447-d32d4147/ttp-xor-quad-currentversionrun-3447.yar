rule TTP_XOR_QUAD_CurrentVersionRun_3447 {
  strings:
    $key_3447 = { 67 28 [2] 43 26 [2] 68 0a [2] 46 28 [2] 52 33 [2] 5d 29 [2] 43 34 [2] 41 35 [2] 5a 33 [2] 46 34 [2] 5a 1b }

  condition:
    any of them
}