rule TTP_XOR_QUAD_CurrentVersionRun_2737 {
  strings:
    $key_2737 = { 74 58 [2] 50 56 [2] 7b 7a [2] 55 58 [2] 41 43 [2] 4e 59 [2] 50 44 [2] 52 45 [2] 49 43 [2] 55 44 [2] 49 6b }

  condition:
    any of them
}