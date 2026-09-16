rule TTP_XOR_QUAD_CurrentVersionRun_7a47 {
  strings:
    $key_7a47 = { 29 28 [2] 0d 26 [2] 26 0a [2] 08 28 [2] 1c 33 [2] 13 29 [2] 0d 34 [2] 0f 35 [2] 14 33 [2] 08 34 [2] 14 1b }

  condition:
    any of them
}