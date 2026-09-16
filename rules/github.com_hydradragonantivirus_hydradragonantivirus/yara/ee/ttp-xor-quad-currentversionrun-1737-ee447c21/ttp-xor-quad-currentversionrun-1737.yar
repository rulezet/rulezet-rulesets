rule TTP_XOR_QUAD_CurrentVersionRun_1737 {
  strings:
    $key_1737 = { 44 58 [2] 60 56 [2] 4b 7a [2] 65 58 [2] 71 43 [2] 7e 59 [2] 60 44 [2] 62 45 [2] 79 43 [2] 65 44 [2] 79 6b }

  condition:
    any of them
}