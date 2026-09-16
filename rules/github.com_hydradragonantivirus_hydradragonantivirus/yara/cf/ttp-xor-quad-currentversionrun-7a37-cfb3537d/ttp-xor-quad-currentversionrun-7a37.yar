rule TTP_XOR_QUAD_CurrentVersionRun_7a37 {
  strings:
    $key_7a37 = { 29 58 [2] 0d 56 [2] 26 7a [2] 08 58 [2] 1c 43 [2] 13 59 [2] 0d 44 [2] 0f 45 [2] 14 43 [2] 08 44 [2] 14 6b }

  condition:
    any of them
}