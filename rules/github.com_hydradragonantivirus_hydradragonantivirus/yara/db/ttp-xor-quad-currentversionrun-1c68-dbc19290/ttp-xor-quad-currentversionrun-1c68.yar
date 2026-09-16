rule TTP_XOR_QUAD_CurrentVersionRun_1c68 {
  strings:
    $key_1c68 = { 4f 07 [2] 6b 09 [2] 40 25 [2] 6e 07 [2] 7a 1c [2] 75 06 [2] 6b 1b [2] 69 1a [2] 72 1c [2] 6e 1b [2] 72 34 }

  condition:
    any of them
}