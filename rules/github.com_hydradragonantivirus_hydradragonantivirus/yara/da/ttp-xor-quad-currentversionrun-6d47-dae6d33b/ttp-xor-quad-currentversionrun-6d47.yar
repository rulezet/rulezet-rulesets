rule TTP_XOR_QUAD_CurrentVersionRun_6d47 {
  strings:
    $key_6d47 = { 3e 28 [2] 1a 26 [2] 31 0a [2] 1f 28 [2] 0b 33 [2] 04 29 [2] 1a 34 [2] 18 35 [2] 03 33 [2] 1f 34 [2] 03 1b }

  condition:
    any of them
}