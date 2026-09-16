rule TTP_XOR_QUAD_CurrentVersionRun_5757 {
  strings:
    $key_5757 = { 04 38 [2] 20 36 [2] 0b 1a [2] 25 38 [2] 31 23 [2] 3e 39 [2] 20 24 [2] 22 25 [2] 39 23 [2] 25 24 [2] 39 0b }

  condition:
    any of them
}