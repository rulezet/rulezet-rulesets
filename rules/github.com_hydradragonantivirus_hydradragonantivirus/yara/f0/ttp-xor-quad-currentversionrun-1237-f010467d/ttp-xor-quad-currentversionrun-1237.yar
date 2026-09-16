rule TTP_XOR_QUAD_CurrentVersionRun_1237 {
  strings:
    $key_1237 = { 41 58 [2] 65 56 [2] 4e 7a [2] 60 58 [2] 74 43 [2] 7b 59 [2] 65 44 [2] 67 45 [2] 7c 43 [2] 60 44 [2] 7c 6b }

  condition:
    any of them
}