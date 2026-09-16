rule TTP_XOR_QUAD_CurrentVersionRun_1357 {
  strings:
    $key_1357 = { 40 38 [2] 64 36 [2] 4f 1a [2] 61 38 [2] 75 23 [2] 7a 39 [2] 64 24 [2] 66 25 [2] 7d 23 [2] 61 24 [2] 7d 0b }

  condition:
    any of them
}