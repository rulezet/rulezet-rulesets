rule TTP_XOR_QUAD_CurrentVersionRun_2f47 {
  strings:
    $key_2f47 = { 7c 28 [2] 58 26 [2] 73 0a [2] 5d 28 [2] 49 33 [2] 46 29 [2] 58 34 [2] 5a 35 [2] 41 33 [2] 5d 34 [2] 41 1b }

  condition:
    any of them
}