rule TTP_XOR_QUAD_CurrentVersionRun_2b47 {
  strings:
    $key_2b47 = { 78 28 [2] 5c 26 [2] 77 0a [2] 59 28 [2] 4d 33 [2] 42 29 [2] 5c 34 [2] 5e 35 [2] 45 33 [2] 59 34 [2] 45 1b }

  condition:
    any of them
}