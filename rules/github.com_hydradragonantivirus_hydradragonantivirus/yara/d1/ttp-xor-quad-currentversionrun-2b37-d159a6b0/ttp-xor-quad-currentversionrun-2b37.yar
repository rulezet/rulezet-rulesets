rule TTP_XOR_QUAD_CurrentVersionRun_2b37 {
  strings:
    $key_2b37 = { 78 58 [2] 5c 56 [2] 77 7a [2] 59 58 [2] 4d 43 [2] 42 59 [2] 5c 44 [2] 5e 45 [2] 45 43 [2] 59 44 [2] 45 6b }

  condition:
    any of them
}