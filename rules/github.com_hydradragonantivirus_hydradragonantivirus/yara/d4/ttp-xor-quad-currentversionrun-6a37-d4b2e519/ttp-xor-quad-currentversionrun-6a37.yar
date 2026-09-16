rule TTP_XOR_QUAD_CurrentVersionRun_6a37 {
  strings:
    $key_6a37 = { 39 58 [2] 1d 56 [2] 36 7a [2] 18 58 [2] 0c 43 [2] 03 59 [2] 1d 44 [2] 1f 45 [2] 04 43 [2] 18 44 [2] 04 6b }

  condition:
    any of them
}