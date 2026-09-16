rule TTP_XOR_QUAD_CurrentVersionRun_6b37 {
  strings:
    $key_6b37 = { 38 58 [2] 1c 56 [2] 37 7a [2] 19 58 [2] 0d 43 [2] 02 59 [2] 1c 44 [2] 1e 45 [2] 05 43 [2] 19 44 [2] 05 6b }

  condition:
    any of them
}