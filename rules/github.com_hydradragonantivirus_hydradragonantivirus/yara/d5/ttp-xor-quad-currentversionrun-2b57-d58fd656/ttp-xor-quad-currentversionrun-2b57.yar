rule TTP_XOR_QUAD_CurrentVersionRun_2b57 {
  strings:
    $key_2b57 = { 78 38 [2] 5c 36 [2] 77 1a [2] 59 38 [2] 4d 23 [2] 42 39 [2] 5c 24 [2] 5e 25 [2] 45 23 [2] 59 24 [2] 45 0b }

  condition:
    any of them
}