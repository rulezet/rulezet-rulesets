rule TTP_XOR_QUAD_CurrentVersionRun_2237 {
  strings:
    $key_2237 = { 71 58 [2] 55 56 [2] 7e 7a [2] 50 58 [2] 44 43 [2] 4b 59 [2] 55 44 [2] 57 45 [2] 4c 43 [2] 50 44 [2] 4c 6b }

  condition:
    any of them
}