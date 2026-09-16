rule TTP_XOR_QUAD_CurrentVersionRun_5837 {
  strings:
    $key_5837 = { 0b 58 [2] 2f 56 [2] 04 7a [2] 2a 58 [2] 3e 43 [2] 31 59 [2] 2f 44 [2] 2d 45 [2] 36 43 [2] 2a 44 [2] 36 6b }

  condition:
    any of them
}